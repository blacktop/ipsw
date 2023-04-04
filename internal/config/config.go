// Package config is used to load the configuration file
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type daemon struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Socket string `json:"socket"`
	Debug  bool   `json:"debug"`
}

type database struct {
	Name     string `json:"database"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSLMode  string `json:"sslmode"`
}

// Config is the configuration struct
type Config struct {
	Daemon   daemon   `json:"daemon"`
	Database database `json:"database"`
}

func (c *Config) verify() error {
	if c.Daemon.Host == "" && c.Daemon.Port == 0 && c.Daemon.Socket == "" {
		// c.Daemon.Socket = "/var/run/ipsw.sock"
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("config: failed to get user home directory: %v", err)
		}
		c.Daemon.Socket = filepath.Join(home, ".config", "ipsw", "ipsw.sock")
	} else if c.Daemon.Host != "" && c.Daemon.Socket != "" {
		return fmt.Errorf("config: host and socket cannot be set at the same time")
	} else if c.Daemon.Host != "" && c.Daemon.Port == 0 {
		return fmt.Errorf("config: port must be set if host is set")
	} else if c.Daemon.Host == "" && c.Daemon.Port != 0 {
		c.Daemon.Host = "localhost"
	}

	return nil
}

// LoadConfig loads the configuration file
func LoadConfig() (*Config, error) {
	var c *Config

	if err := viper.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("config: failed to unmarshal: %v", err)
	}

	if err := c.verify(); err != nil {
		return nil, fmt.Errorf("config: failed to verify: %v", err)
	}

	return c, nil
}
