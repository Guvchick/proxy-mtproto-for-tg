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
	ProxyTag string `yaml:"proxy_tag"` // optional: 32-hex Telegram proxy tag

	AddrFamily string `yaml:"addr_family"` // "ipv4" | "ipv6" | "prefer-ipv6"

	ReadBufSize  int `yaml:"read_buf_size"`
	WriteBufSize int `yaml:"write_buf_size"`

	Metrics MetricsConfig `yaml:"metrics"`
	Log     LogConfig     `yaml:"log"`
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
