// Package cmd provides command-line interface functionality for the CLI Proxy API server.
// It includes authentication flows for various AI service providers, service startup,
// and other command-line operations.
package cmd

import (
	"context"
	"errors"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/secretstore"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/supply/phone"
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
		log.Infof("secret store ready at %s (mode %s, unlocked)", path, store.Mode())
	case !store.Initialized():
		log.Warnf("secret store at %s is not initialized; set a master passphrase before storing secrets", path)
	default:
		log.Warnf("secret store at %s is locked (mode %s); unlock with the master passphrase to use secrets", path, store.Mode())
	}
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
	installSupply(cfg, configPath)
	management.SetSupplyReloader(func() { installSupply(cfg, configPath) })
}

// installSupply (re)builds and installs the process-wide supply service.
func installSupply(cfg *config.Config, configPath string) {
	registry := supply.NewRegistry()
	registry.SetLedger(loadSupplyLedger(cfg, configPath))
	if provider, errPhone := buildPhoneProvider(cfg, configPath, registry.Ledger()); errPhone != nil {
		log.Warnf("phone supply kind disabled: %v", errPhone)
	} else if provider != nil {
		if errRegister := registry.Register(provider); errRegister != nil {
			log.Warnf("phone supply kind not registered: %v", errRegister)
		}
	}
	supply.SetDefault(registry)
	log.Infof("account supply ready at %s", supplyStateSummary(registry))
}

// supplyStateDir resolves where the supply service keeps its on-disk state.
func supplyStateDir(cfg *config.Config, configPath string) string {
	configured := ""
	if cfg != nil {
		configured = cfg.Supply.WithDefaults().StorageDir
	}
	return supply.StateDir(filepath.Dir(configPath), configured)
}

// loadSupplyLedger reads the cross-kind identity ledger.
//
// It is loaded here, once, and injected into the registry and every provider:
// the ledger is one document shared by all kinds, so a provider that loaded its
// own copy would drift from the others. A decode failure is reported but not
// fatal — a corrupt ledger must not stop the server from starting, and the next
// write rewrites it.
func loadSupplyLedger(cfg *config.Config, configPath string) *supply.Ledger {
	ledger, errLoad := supply.LoadLedger(supply.LedgerPath(supplyStateDir(cfg, configPath)))
	if errLoad != nil {
		log.Warnf("supply ledger unreadable, starting empty: %v", errLoad)
		return supply.NewLedger()
	}
	return ledger
}

// buildPhoneProvider assembles the phone provider from configuration and the
// host secret store.
//
// It returns (nil, nil) when the kind is disabled or no platform credential is
// stored, which is the not-configured state. A locked store is treated the same
// way: the credential cannot be read, so the kind is not offered until unlock.
func buildPhoneProvider(cfg *config.Config, configPath string, ledger *supply.Ledger) (*phone.ProviderImpl, error) {
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
		Ledger:   ledger,
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
