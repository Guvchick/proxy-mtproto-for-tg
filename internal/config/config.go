package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen   string `yaml:"listen"`
	Secret   string `yaml:"secret"`
	Workers  int    `yaml:"workers"`
	ProxyTag string `yaml:"proxy_tag"`

	AddrFamily string `yaml:"addr_family"` // "ipv4" | "ipv6" | "prefer-ipv6"

	ReadBufSize  int `yaml:"read_buf_size"`
	WriteBufSize int `yaml:"write_buf_size"`

	// SkipHMACCheck disables the 4-byte HMAC validation in fake-TLS ClientHello.
	// Enable only for debugging — allows replay attacks.
	SkipHMACCheck bool `yaml:"skip_hmac_check"`

	// SkipTimestampCheck disables the ±1h timestamp window in fake-TLS.
	SkipTimestampCheck bool `yaml:"skip_timestamp_check"`

	// Upstream — when set, the proxy relays to this server instead of
	// Telegram DCs directly.  Useful for chaining:
	//   client → front (RU) → upstream (abroad) → Telegram DC
	Upstream *UpstreamConfig `yaml:"upstream"`

	Metrics MetricsConfig `yaml:"metrics"`
	Log     LogConfig     `yaml:"log"`
}

// UpstreamConfig describes the backend server the proxy connects to.
type UpstreamConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

func (u *UpstreamConfig) Addr() string {
	return fmt.Sprintf("%s:%d", u.Host, u.Port)
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type LogConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // json | text
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg := defaults()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("secret is required")
	}
	return cfg, nil
}

func defaults() *Config {
	return &Config{
		Listen:       "0.0.0.0:443",
		AddrFamily:   "ipv4",
		ReadBufSize:  4096,
		WriteBufSize: 4096,
		Metrics: MetricsConfig{
			Enabled: true,
			Listen:  "0.0.0.0:9090",
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
		},
	}
}
