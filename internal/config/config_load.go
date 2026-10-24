package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// LoadConfig reads a YAML configuration file from the given path,
// unmarshals it into a Config struct, applies environment variable overrides,
// and returns it.
//
// Parameters:
//   - configFile: The path to the YAML configuration file
//
// Returns:
//   - *Config: The loaded configuration
//   - error: An error if the configuration could not be loaded
func LoadConfig(configFile string) (*Config, error) {
	return LoadConfigOptional(configFile, false)
}

// LoadConfigOptional reads YAML from configFile.
// If optional is true and the file is missing, it returns an empty Config.
// If optional is true and the file is empty or invalid, it returns an empty Config.
func LoadConfigOptional(configFile string, optional bool) (*Config, error) {
	// Read the entire configuration file into memory.
	data, err := os.ReadFile(configFile)
	if err != nil {
		if optional {
			if os.IsNotExist(err) || errors.Is(err, syscall.EISDIR) {
				// Missing and optional: return empty config (cloud deploy standby).
				cfg := &Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
				cfg.NormalizePluginsConfig()
				return cfg, nil
			}
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// In cloud deploy mode (optional=true), if file is empty or contains only whitespace, return empty config.
	if optional && len(bytes.TrimSpace(data)) == 0 {
		cfg := &Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
		cfg.NormalizePluginsConfig()
		return cfg, nil
	}

	if errValidate := validateCredentialWeightYAML(data); errValidate != nil {
		if optional {
			cfgOptional := &Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
			cfgOptional.NormalizePluginsConfig()
			return cfgOptional, nil
		}
		return nil, errValidate
	}

	// Unmarshal the YAML data into the Config struct.
	var cfg Config
	// Set defaults before unmarshal so that absent keys keep defaults.
	cfg.Host = "" // Default empty: binds to all interfaces (IPv4 + IPv6)
	cfg.LoggingToFile = false
	cfg.LogsMaxTotalSizeMB = 0
	cfg.ErrorLogsMaxFiles = 10
	cfg.UsageStatisticsEnabled = false
	cfg.RedisUsageQueueRetentionSeconds = 60
	cfg.DisableCooling = false
	cfg.SaveCooldownStatus = false
	cfg.TransientErrorCooldownSeconds = 0
	cfg.DisableImageGeneration = DisableImageGenerationOff
	cfg.WebsocketAuth = true
	cfg.Pprof.Enable = false
	cfg.Pprof.Addr = DefaultPprofAddr
	cfg.Discovery.Enabled = false
	cfg.Discovery.ServiceType = DefaultDiscoveryServiceType
	cfg.Discovery.Subtypes = []string{"_chat-completions", "_responses", "_messages", "_generate-content", "_interactions"}
	cfg.RemoteManagement.PanelGitHubRepository = DefaultPanelGitHubRepository
	cfg.RequestRetry = 3
	cfg.MaxRetryInterval = 30
	cfg.CredentialInFlight = DefaultCredentialInFlightConfig()
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		if optional {
			// In cloud deploy mode, if YAML parsing fails, return empty config instead of error.
			cfgOptional := &Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
			cfgOptional.NormalizePluginsConfig()
			return cfgOptional, nil
		}
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	if errValidate := validateTrustedProxies(cfg.TrustedProxies); errValidate != nil {
		return nil, errValidate
	}

	cfg.CredentialConcurrency = cfg.CredentialConcurrency.WithDefaults()
	if errValidate := cfg.CredentialInFlight.Validate(); errValidate != nil {
		return nil, errValidate
	}
	if cfg.Discovery.ServiceType == "" {
		cfg.Discovery.ServiceType = DefaultDiscoveryServiceType
	}
	if len(cfg.Discovery.Subtypes) == 0 {
		cfg.Discovery.Subtypes = []string{"_chat-completions", "_responses", "_messages", "_generate-content", "_interactions"}
	}
	if errValidate := cfg.Codex.LiveMediaRelay.Validate(); errValidate != nil {
		return nil, errValidate
	}
	if errValidate := cfg.ValidateCredentialWeights(); errValidate != nil {
		return nil, errValidate
	}

	// Hash remote management keys if plaintext is detected (nested)
	// We consider a value to be already hashed if it looks like a bcrypt hash ($2a$, $2b$, or $2y$ prefix).
	if errHash := hashManagementKey(configFile, data, &cfg.RemoteManagement.SecretKey, "secret-key"); errHash != nil {
		return nil, errHash
	}
	if errHash := hashManagementKey(configFile, data, &cfg.RemoteManagement.AutomationKey, "automation-key"); errHash != nil {
		return nil, errHash
	}

	cfg.RemoteManagement.PanelGitHubRepository = strings.TrimSpace(cfg.RemoteManagement.PanelGitHubRepository)
	if cfg.RemoteManagement.PanelGitHubRepository == "" {
		cfg.RemoteManagement.PanelGitHubRepository = DefaultPanelGitHubRepository
	}

	cfg.Pprof.Addr = strings.TrimSpace(cfg.Pprof.Addr)
	if cfg.Pprof.Addr == "" {
		cfg.Pprof.Addr = DefaultPprofAddr
	}

	if cfg.LogsMaxTotalSizeMB < 0 {
		cfg.LogsMaxTotalSizeMB = 0
	}

	if cfg.ErrorLogsMaxFiles < 0 {
		cfg.ErrorLogsMaxFiles = 10
	}

	if cfg.RedisUsageQueueRetentionSeconds <= 0 {
		cfg.RedisUsageQueueRetentionSeconds = 60
	} else if cfg.RedisUsageQueueRetentionSeconds > 3600 {
		log.WithField("value", cfg.RedisUsageQueueRetentionSeconds).Warn("redis-usage-queue-retention-seconds too large; clamping to 3600")
		cfg.RedisUsageQueueRetentionSeconds = 3600
	}

	if cfg.MaxRetryCredentials < 0 {
		cfg.MaxRetryCredentials = 0
	}

	cfg.NormalizePluginsConfig()
	if errResolvePluginsDir := cfg.ResolvePluginsDir(); errResolvePluginsDir != nil && cfg.Plugins.Enabled {
		return nil, errResolvePluginsDir
	}

	// Sanitize Gemini API key configuration and migrate legacy entries.
	cfg.SanitizeGeminiKeys()

	// Sanitize native Interactions API key configuration.
	cfg.SanitizeInteractionsKeys()

	// Sanitize Vertex-compatible API keys.
	cfg.SanitizeVertexCompatKeys()

	// Sanitize Codex keys: drop entries without base-url
	cfg.SanitizeCodexKeys()

	// Sanitize xAI keys: drop entries without base-url
	cfg.SanitizeXAIKeys()

	// Sanitize Meta keys.
	cfg.SanitizeMetaKeys()

	// Sanitize Codex header defaults.
	cfg.SanitizeCodexHeaderDefaults()

	// Sanitize Claude header defaults.
	cfg.SanitizeClaudeHeaderDefaults()

	// Sanitize Claude key headers
	cfg.SanitizeClaudeKeys()

	// Sanitize OpenAI compatibility providers: drop entries without base-url
	cfg.SanitizeOpenAICompatibility()

	// Normalize OAuth provider model exclusion map.
	cfg.OAuthExcludedModels = NormalizeOAuthExcludedModels(cfg.OAuthExcludedModels)

	// Normalize global OAuth model name aliases.
	cfg.SanitizeOAuthModelAlias()

	// Normalize global OAuth model settings.
	cfg.SanitizeOAuthSettings()

	// Normalize global OAuth request-scoped error rules.
	cfg.SanitizeOAuthRequestScopedErrors()

	// Validate raw payload rules and drop invalid entries.
	cfg.SanitizePayloadRules()

	// Only conflicting legacy fields are removed on load. A legacy-only document
	// stays legacy until a v8 configuration write explicitly migrates it.
	current, errRead := os.ReadFile(configFile)
	if errRead != nil {
		return nil, errRead
	}
	cleaned, changed, errLayout := NormalizeConfigLayout(current, false)
	if errLayout != nil {
		return nil, errLayout
	}
	if changed {
		if errWrite := os.WriteFile(configFile, cleaned, 0600); errWrite != nil {
			return nil, fmt.Errorf("clean conflicting config fields: %w", errWrite)
		}
	}

	// Return the populated configuration struct.
	return &cfg, nil
}

// hashManagementKey replaces one plaintext management key with its bcrypt hash
// and writes that hash back to the config file, so the next start has no
// plaintext left to convert. A value that already looks like a hash is left
// untouched, and an empty value is not a key at all.
//
// yamlKey is both the struct field's YAML name and the scalar that gets
// rewritten, which is why the two keys share this function instead of each
// carrying its own copy of the write-back.
func hashManagementKey(configFile string, data []byte, field *string, yamlKey string) error {
	if field == nil || *field == "" || looksLikeBcrypt(*field) {
		return nil
	}
	hashed, errHash := hashSecret(*field)
	if errHash != nil {
		return fmt.Errorf("failed to hash %s: %w", yamlKey, errHash)
	}
	*field = hashed

	// Preserve YAML comments and ordering; update only the nested key. The block
	// may still be spelled with its pre-v8 name, so the path is chosen by what
	// the document actually contains.
	path := []string{"remote-management", yamlKey}
	var source yaml.Node
	if yaml.Unmarshal(data, &source) == nil && len(source.Content) > 0 && yamlPath(expandConfigAliases(source.Content[0]), "management."+yamlKey) != nil {
		path[0] = "management"
	}
	_ = SaveConfigPreserveCommentsUpdateNestedScalar(configFile, path, hashed)
	return nil
}
