package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	BurpWSURL        string `json:"burpWsUrl"`
	BurpAuthToken    string `json:"burpAuthToken"`
	RequestTimeoutMS int    `json:"requestTimeoutMs"`
	DaemonSocketPath string `json:"daemonSocketPath"`
	Output           string `json:"output"`
	Debug            bool   `json:"debug"`
	LogPath          string `json:"logPath"`
}

type Overrides struct {
	ConfigPath       string
	BurpWSURL        string
	BurpAuthToken    string
	RequestTimeoutMS int
	Output           string
	Debug            bool
}

func Load(overrides Overrides) (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		BurpWSURL:        "ws://127.0.0.1:8198",
		BurpAuthToken:    "",
		RequestTimeoutMS: 30000,
		DaemonSocketPath: filepath.Join(home, ".agent-burp", "run", "daemon.sock"),
		Output:           "text",
		Debug:            false,
		LogPath:          filepath.Join(home, ".agent-burp", "logs", "daemon.log"),
	}

	mergeFromPath(&cfg, filepath.Join(home, ".agent-burp", "config.json"))
	mergeFromPath(&cfg, "agent-burp.json")

	if overrides.ConfigPath != "" {
		if err := mergeFromPathRequired(&cfg, overrides.ConfigPath); err != nil {
			return Config{}, err
		}
	}

	mergeFromEnv(&cfg)
	mergeFromOverrides(&cfg, overrides)

	if cfg.BurpWSURL == "" {
		return Config{}, errors.New("burp WS URL cannot be empty")
	}
	if cfg.RequestTimeoutMS <= 0 {
		return Config{}, errors.New("requestTimeoutMs must be > 0")
	}

	return cfg, nil
}

func EnsureRuntimeDirs(cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.DaemonSocketPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.LogPath), 0o755); err != nil {
		return err
	}
	return nil
}

type fileConfig struct {
	BurpWSURL        *string `json:"burpWsUrl"`
	BurpAuthToken    *string `json:"burpAuthToken"`
	RequestTimeoutMS *int    `json:"requestTimeoutMs"`
	DaemonSocketPath *string `json:"daemonSocketPath"`
	Output           *string `json:"output"`
	Debug            *bool   `json:"debug"`
	LogPath          *string `json:"logPath"`
}

func mergeFromPath(cfg *Config, p string) {
	_ = mergeFromPathRequired(cfg, p)
}

func mergeFromPathRequired(cfg *Config, p string) error {
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var f fileConfig
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}

	if f.BurpWSURL != nil {
		cfg.BurpWSURL = *f.BurpWSURL
	}
	if f.BurpAuthToken != nil {
		cfg.BurpAuthToken = *f.BurpAuthToken
	}
	if f.RequestTimeoutMS != nil {
		cfg.RequestTimeoutMS = *f.RequestTimeoutMS
	}
	if f.DaemonSocketPath != nil {
		cfg.DaemonSocketPath = *f.DaemonSocketPath
	}
	if f.Output != nil {
		cfg.Output = *f.Output
	}
	if f.Debug != nil {
		cfg.Debug = *f.Debug
	}
	if f.LogPath != nil {
		cfg.LogPath = *f.LogPath
	}

	return nil
}

func mergeFromEnv(cfg *Config) {
	if v := os.Getenv("AGENT_BURP_WS_URL"); v != "" {
		cfg.BurpWSURL = v
	}
	if v := os.Getenv("AGENT_BURP_AUTH_TOKEN"); v != "" {
		cfg.BurpAuthToken = v
	}
	if v := os.Getenv("AGENT_BURP_TIMEOUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RequestTimeoutMS = n
		}
	}
	if v := os.Getenv("AGENT_BURP_OUTPUT"); v != "" {
		cfg.Output = v
	}
	if v := os.Getenv("AGENT_BURP_SOCKET"); v != "" {
		cfg.DaemonSocketPath = v
	}
	if v := os.Getenv("AGENT_BURP_DEBUG"); v != "" {
		cfg.Debug = v == "1" || v == "true"
	}
	if v := os.Getenv("AGENT_BURP_LOG_PATH"); v != "" {
		cfg.LogPath = v
	}
}

func mergeFromOverrides(cfg *Config, ov Overrides) {
	if ov.BurpWSURL != "" {
		cfg.BurpWSURL = ov.BurpWSURL
	}
	if ov.BurpAuthToken != "" {
		cfg.BurpAuthToken = ov.BurpAuthToken
	}
	if ov.RequestTimeoutMS > 0 {
		cfg.RequestTimeoutMS = ov.RequestTimeoutMS
	}
	if ov.Output != "" {
		cfg.Output = ov.Output
	}
	if ov.Debug {
		cfg.Debug = true
	}
}
