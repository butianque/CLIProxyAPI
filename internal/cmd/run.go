// Package cmd provides command-line interface functionality for the CLI Proxy API server.
// It includes authentication flows for various AI service providers, service startup,
// and other command-line operations.
package cmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/email"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/phone"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy"
	log "github.com/sirupsen/logrus"
)

// initSecretStore installs the process-wide secret store used by the management
// API and by plugins through the host.secret.* callbacks. It is best-effort: a
// store that cannot be opened disables the feature instead of blocking startup.
func initSecretStore(configPath string) {
	path := secretstore.DefaultPath(configPath)
	store, errOpen := secretstore.Open(path)
	if errOpen != nil {
		log.Warnf("secret store disabled: %v", errOpen)
		secretstore.Configure(nil)
		return
	}
	secretstore.Configure(store)
	switch {
	case store.Unlocked():
		log.Infof("secret store ready at %s (mode %s, backend access %s, key protection %s)",
			path, store.Mode(), store.SystemAccess(), sealLabel(store.SealMedium()))
	case !store.Initialized():
		log.Warnf("secret store at %s is not initialized; set a master passphrase before storing secrets", path)
	default:
		log.Warnf("secret store at %s is locked (mode %s); unlock with the master passphrase to use secrets", path, store.Mode())
	}
	startSealRotation(store)
}

// sealLabel renders a seal medium for a log line.
func sealLabel(medium string) string {
	if medium == "" {
		return "none"
	}
	return medium
}

// sealRotationInterval is how often the machine key is re-wrapped. A day is short
// enough that a copied seal file goes stale within a known window and long enough
// that the rewrite is invisible. CPA_SECRET_SEAL_ROTATE_HOURS overrides it; zero
// disables rotation.
const defaultSealRotationHours = 24

func sealRotationInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("CPA_SECRET_SEAL_ROTATE_HOURS"))
	if raw != "" {
		if hours, errAtoi := strconv.Atoi(raw); errAtoi == nil {
			return time.Duration(hours) * time.Hour
		}
		log.Warnf("CPA_SECRET_SEAL_ROTATE_HOURS=%q is not a number; using %d hours", raw, defaultSealRotationHours)
	}
	return defaultSealRotationHours * time.Hour
}

// startSealRotation re-wraps the machine key on a schedule.
//
// What this is: the storage key is sealed again with fresh OS-supplied
// randomness, so the artifact on disk is refreshed and the rotation count moves.
// What this is not: it does not revoke a copy of the old seal file — that copy
// still unseals, because the storage key itself has not changed. Rotation bounds
// how long a copied artifact stays current and gives the seal a heartbeat the
// operator can see; replacing the storage key is a separate, destructive action.
func startSealRotation(store *secretstore.Store) {
	interval := sealRotationInterval()
	if interval <= 0 || store == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			// Unattended access can be switched on long after startup, so the
			// medium is checked per tick instead of once here: a store that is
			// passphrase-only today may hold a machine key tomorrow.
			if store.SealMedium() == "" {
				continue
			}
			if errRotate := store.RotateSeal(); errRotate != nil {
				log.Warnf("secret store: seal rotation failed: %v", errRotate)
				continue
			}
			log.Infof("secret store: machine key re-sealed (%s)", sealLabel(store.SealMedium()))
		}
	}()
}

// initSupply installs the process-wide account-supply service used by plugins
// through the host.supply.* callbacks.
//
// A kind is registered only when its configuration opts it in and its platform
// credential is readable from the host secret store. A locked or empty store,
// or a kind left disabled, leaves the kind out rather than failing startup: an
// unconfigured kind is the honest state, and the management surface reports it
// as such.
func initSupply(cfg *config.Config, configPath string) {
	// Install the process-wide exit before anything is built: every consumer
	// asks EffectiveProxyURL, and that is what makes "one exit, one edit" true
	// without touching those call sites.
	installGlobalEgress(cfg, configPath)
	installSupply(cfg, configPath)
	management.SetSupplyReloader(func() { installSupply(cfg, configPath) })
	// Credentials name their exit by pool id, and this is where the pool lives,
	// so the resolver is installed here rather than inside the auth store. It is
	// installed before the service is built, which is before any auth file is
	// read, so no credential is ever loaded with an unresolved id.
	sdkAuth.SetEgressResolver(egressResolver(supplyStateDir(cfg, configPath)))
}

// installSupply (re)builds and installs the process-wide supply service.
func installSupply(cfg *config.Config, configPath string) {
	registry := supply.NewRegistry()
	registry.SetPool(loadSupplyPool(cfg, configPath))
	if provider, errPhone := buildPhoneProvider(cfg, configPath, registry.Pool()); errPhone != nil {
		log.Warnf("phone supply kind disabled: %v", errPhone)
	} else if provider != nil {
		if errRegister := registry.Register(provider); errRegister != nil {
			log.Warnf("phone supply kind not registered: %v", errRegister)
		}
	}
	if provider, errEmail := buildEmailProvider(cfg, configPath, registry.Pool()); errEmail != nil {
		log.Warnf("email supply kind disabled: %v", errEmail)
	} else if provider != nil {
		if errRegister := registry.Register(provider); errRegister != nil {
			log.Warnf("email supply kind not registered: %v", errRegister)
		}
	}
	supply.SetDefault(registry)
	log.Infof("account supply ready at %s", supplyStateSummary(registry))
}

// buildEmailProvider assembles the email provider.
//
// Unlike the phone kind it does not require an unlocked store at construction:
// every mailbox carries its own secret name, and the value is read per call. A
// locked store therefore still yields a provider — one that reports "unknown"
// rather than "absent", which is the honest answer and the one the panel needs
// in order to offer an unlock.
func buildEmailProvider(cfg *config.Config, configPath string, pool *supply.Pool) (*email.ProviderImpl, error) {
	if cfg == nil {
		return nil, nil
	}
	supplyCfg := cfg.Supply.WithDefaults()
	if supplyCfg.Email.Disabled {
		return nil, nil
	}
	stateDir := supplyStateDir(cfg, configPath)
	return email.New(email.Config{
		ChannelsPath:  supply.ChannelPath(stateDir),
		Pool:          pool,
		PoolPath:      supply.PoolPath(stateDir),
		PollWindow:    time.Duration(supplyCfg.Email.PollWindowHours) * time.Hour,
		MaxMessages:   supplyCfg.Email.MaxMessages,
		Egress:        supplyEgress(cfg),
		ResolveEgress: egressResolver(stateDir),
	})
}

// egressResolver reads the proxy pool once per call and resolves an id.
//
// Reading per call rather than caching is deliberate: an exit can be replaced
// while the process runs, and a cached address would keep sending traffic from
// the retired one until the next restart.
func egressResolver(stateDir string) func(id int) (string, error) {
	poolPath := supply.EgressPoolPath(stateDir)
	return func(id int) (string, error) {
		pool, errLoad := supply.LoadEgressPool(poolPath)
		if errLoad != nil {
			return "", errLoad
		}
		return pool.ResolveRef(supply.EgressRef{ID: id})
	}
}

// supplyStateDir resolves where the supply service keeps its on-disk state.
func supplyStateDir(cfg *config.Config, configPath string) string {
	configured := ""
	if cfg != nil {
		configured = cfg.Supply.WithDefaults().StorageDir
	}
	return supply.StateDir(filepath.Dir(configPath), configured)
}

// supplyEgress is the address supply traffic leaves through.
//
// Supply has no exit of its own: it leaves from the process-wide one, because a
// rented number and the account it registers are judged together, and reading a
// mailbox from one address while signing up from another is the pattern fraud
// scoring looks for. A channel may still override this per connection.
func supplyEgress(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.EffectiveProxyURL()
}

// installGlobalEgress points the process at the exit the pool designates.
//
// The resolver is installed once rather than resolved once: the pool's default
// can change while the server runs (that is the point of it), and every consumer
// asks EffectiveProxyURL on its own request. Nothing has to be re-applied, and a
// stale copy can never outlive the edit.
func installGlobalEgress(cfg *config.Config, configPath string) {
	if cfg == nil {
		return
	}
	poolPath := supply.EgressPoolPath(supplyStateDir(cfg, configPath))
	config.SetEgressDefaultResolver(func() (string, bool) { return supply.GlobalEgress(poolPath) })
}

// loadSupplyPool reads the cross-kind identity pool.
//
// It is loaded here, once, and injected into the registry and every provider:
// the pool is one document shared by all kinds, so a provider that loaded its
// own copy would drift from the others. A decode failure is reported but not
// fatal — a corrupt pool must not stop the server from starting, and the next
// write rewrites it.
//
// The channel document is migrated on the way: a channel used to be able to
// declare a token-based mailbox transport, which put one bought address in the
// same table as a service that mints addresses. Those identities are moved into
// the pool here so an existing installation keeps reading its mail instead of
// being refused at load time. A migration failure is a warning for the same
// reason a decode failure is: the server must still start.
func loadSupplyPool(cfg *config.Config, configPath string) *supply.Pool {
	stateDir := supplyStateDir(cfg, configPath)
	pool, errLoad := supply.LoadPool(supply.PoolPath(stateDir))
	if errLoad != nil {
		log.Warnf("supply pool unreadable, starting empty: %v", errLoad)
		pool = supply.NewPool()
	}
	migrateMailboxesIntoPool(stateDir, pool)
	return pool
}

// migrateMailboxesIntoPool moves mailbox identities a channel can no longer own
// into the pool.
func migrateMailboxesIntoPool(stateDir string, pool *supply.Pool) {
	if pool == nil {
		return
	}
	store, errLoad := supply.LoadChannels(supply.ChannelPath(stateDir))
	if errLoad != nil {
		log.Warnf("supply channels unreadable, skipping the mailbox migration: %v", errLoad)
		return
	}
	moved, errMigrate := supply.MigrateChannelsToPool(store, pool, time.Now().Unix())
	if errMigrate != nil {
		log.Warnf("supply mailbox migration incomplete: %v", errMigrate)
	}
	if moved == 0 {
		return
	}
	if errSave := pool.Save(supply.PoolPath(stateDir)); errSave != nil {
		log.Warnf("supply pool not saved after the mailbox migration: %v", errSave)
		return
	}
	log.Infof("moved %d mailbox identities from the channel table into the supply pool", moved)
}

// buildPhoneProvider assembles the phone provider from configuration and the
// host secret store.
//
// It returns (nil, nil) when the kind is disabled or no platform credential is
// stored, which is the not-configured state. A locked store is treated the same
// way: the credential cannot be read, so the kind is not offered until unlock.
func buildPhoneProvider(cfg *config.Config, configPath string, pool *supply.Pool) (*phone.ProviderImpl, error) {
	if cfg == nil {
		return nil, nil
	}
	supplyCfg := cfg.Supply.WithDefaults()
	if supplyCfg.Phone.Disabled {
		return nil, nil
	}
	store := secretstore.Default()
	if store == nil || !store.Unlocked() {
		return nil, nil
	}
	raw, errGet := store.Get(supplyCfg.Phone.APISecret)
	if errGet != nil {
		// Absent is not-configured; anything else is a real read failure.
		if errors.Is(errGet, secretstore.ErrNotFound) {
			return nil, nil
		}
		return nil, errGet
	}
	secret, errParse := phone.ParseHaozhumaSecret(raw)
	if errParse != nil {
		return nil, errParse
	}
	if cookieRaw, errCookie := store.Get(supplyCfg.Phone.CookieSecret); errCookie == nil {
		if cookie, errCookieParse := phone.ParseHaozhumaCookie(cookieRaw); errCookieParse == nil {
			if cookie.Cookie != "" {
				secret.Cookie = cookie.Cookie
			}
			if cookie.WebBase != "" {
				secret.WebBase = cookie.WebBase
			}
		}
	}

	stateDir := strings.TrimSpace(supplyCfg.StorageDir)
	if stateDir == "" {
		stateDir = filepath.Join(filepath.Dir(configPath), "supply")
	}
	return phone.New(phone.Config{
		Provider: supplyCfg.Phone.Provider,
		Secret:   secret,
		Store:    phone.Store{Dir: stateDir},
		Pool:     pool,
		Budget: phone.Budget{
			MaxPerNumberCNY: supplyCfg.Phone.MaxPerNumberCNY,
			MaxTotalCNY:     supplyCfg.Phone.MaxTotalCNY,
		},
		Project: phone.Project{
			SID:  supplyCfg.Phone.Project,
			Name: supplyCfg.Phone.ProjectName,
		},
		CoolDownSeconds: supplyCfg.Phone.CooldownSeconds,
		Guardrail:       supplyCfg.Phone.GuardrailEnabled(),
		Egress:          supplyEgress(cfg),
	})
}

// supplyStateSummary renders the supply service's kind set for one log line.
func supplyStateSummary(service supply.Supply) string {
	status, errStatus := service.Status(context.Background())
	if errStatus != nil {
		return "status unavailable: " + errStatus.Error()
	}
	if !status.Enabled {
		return "no supply kind configured"
	}
	kinds := make([]string, 0, len(status.Kinds))
	for _, kind := range status.Kinds {
		kinds = append(kinds, string(kind))
	}
	return "kinds " + strings.Join(kinds, ",")
}

// StartService builds and runs the proxy service using the exported SDK.
// It creates a new proxy service instance, sets up signal handling for graceful shutdown,
// and starts the service with the provided configuration.
//
// Parameters:
//   - cfg: The application configuration
//   - configPath: The path to the configuration file
//   - localPassword: Optional password accepted for local management requests
func StartService(cfg *config.Config, configPath string, localPassword string) {
	StartServiceWithPluginHost(cfg, configPath, localPassword, nil)
}

// StartServiceWithPluginHost builds and runs the proxy service with a shared plugin host.
func StartServiceWithPluginHost(cfg *config.Config, configPath string, localPassword string, host *pluginhost.Host, serverOptions ...api.ServerOption) {
	initSecretStore(configPath)
	initSupply(cfg, configPath)
	builder := cliproxy.NewBuilder().
		WithConfig(cfg).
		WithConfigPath(configPath).
		WithLocalManagementPassword(localPassword)
	if host != nil {
		builder = builder.WithPluginHost(host)
	}
	if len(serverOptions) > 0 {
		builder = builder.WithServerOptions(serverOptions...)
	}

	ctxSignal, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	runCtx := ctxSignal
	if localPassword != "" {
		var keepAliveCancel context.CancelFunc
		runCtx, keepAliveCancel = context.WithCancel(ctxSignal)
		builder = builder.WithServerOptions(api.WithKeepAliveEndpoint(10*time.Second, func() {
			log.Warn("keep-alive endpoint idle for 10s, shutting down")
			keepAliveCancel()
		}))
	}

	service, err := builder.Build()
	if err != nil {
		log.Errorf("failed to build proxy service: %v", err)
		return
	}

	err = service.Run(runCtx)
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Errorf("proxy service exited with error: %v", err)
	}
}

// StartServiceBackground starts the proxy service in a background goroutine
// and returns a cancel function for shutdown and a done channel.
func StartServiceBackground(cfg *config.Config, configPath string, localPassword string) (cancel func(), done <-chan struct{}) {
	return StartServiceBackgroundWithPluginHost(cfg, configPath, localPassword, nil)
}

// StartServiceBackgroundWithPluginHost starts the proxy service with a shared plugin host.
func StartServiceBackgroundWithPluginHost(cfg *config.Config, configPath string, localPassword string, host *pluginhost.Host, serverOptions ...api.ServerOption) (cancel func(), done <-chan struct{}) {
	initSecretStore(configPath)
	initSupply(cfg, configPath)
	builder := cliproxy.NewBuilder().
		WithConfig(cfg).
		WithConfigPath(configPath).
		WithLocalManagementPassword(localPassword)
	if host != nil {
		builder = builder.WithPluginHost(host)
	}
	if len(serverOptions) > 0 {
		builder = builder.WithServerOptions(serverOptions...)
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	doneCh := make(chan struct{})

	service, err := builder.Build()
	if err != nil {
		log.Errorf("failed to build proxy service: %v", err)
		close(doneCh)
		return cancelFn, doneCh
	}

	go func() {
		defer close(doneCh)
		if err := service.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Errorf("proxy service exited with error: %v", err)
		}
	}()

	return cancelFn, doneCh
}

// WaitForCloudDeploy waits indefinitely for shutdown signals in cloud deploy mode
// when no configuration file is available.
func WaitForCloudDeploy() {
	// Clarify that we are intentionally idle for configuration and not running the API server.
	log.Info("Cloud deploy mode: No config found; standing by for configuration. API server is not started. Press Ctrl+C to exit.")

	ctxSignal, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Block until shutdown signal is received
	<-ctxSignal.Done()
	log.Info("Cloud deploy mode: Shutdown signal received; exiting")
}
