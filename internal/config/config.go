// Package config is used to load the configuration file
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	env "github.com/caarlos0/env/v8"
	"github.com/spf13/viper"
)

type daemon struct {
	Host    string `json:"host" env:"DAEMON_HOST" envDefault:"localhost"`
	Port    int    `json:"port" env:"DAEMON_PORT" envDefault:"3993"`
	Socket  string `json:"socket" env:"DAEMON_SOCKET"`
	Debug   bool   `json:"debug" env:"DAEMON_DEBUG"`
	LogFile string `json:"logfile" env:"DAEMON_LOGFILE"`
	PemDB   string `json:"pem_db" mapstructure:"pem-db" env:"DAEMON_PEM_DB"`
	SigsDir string `json:"sigs_dir" mapstructure:"sigs-dir" env:"DAEMON_SIGS_DIR"`
}

type database struct {
	Driver    string `json:"driver" env:"DB_DRIVER"`
	Name      string `json:"database" env:"DB_NAME"`
	Path      string `json:"path" env:"DB_PATH"`
	Host      string `json:"host" env:"DB_HOST"`
	Port      string `json:"port" env:"DB_PORT"`
	User      string `json:"user" env:"DB_USER"`
	Password  string `json:"password" env:"DB_PASSWORD"`
	SSLMode   string `json:"sslmode" env:"DB_SSLMODE"`
	BatchSize int    `json:"batchsize" env:"DB_BATCHSIZE" envDefault:"1000"`
}

// Config is the configuration struct
type Config struct {
	Daemon   daemon   `json:"daemon"`
	Database database `json:"database"`
}

func (c *Config) verify() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("config: failed to get user home directory: %v", err)
	}
	// verify daemon
	if c.Daemon.Host == "" && c.Daemon.Port == 0 && c.Daemon.Socket == "" {
		if os.Getenv("IPSW_IN_SNAP") == "1" {
			c.Daemon.Socket = "/var/snap/ipswd/common/ipsw.sock"
		} else {
			c.Daemon.Host = "localhost"
			c.Daemon.Port = 3993
		}
	} else if c.Daemon.Host != "" && c.Daemon.Socket != "" {
		return fmt.Errorf("config: host and socket cannot be set at the same time")
	} else if c.Daemon.Host != "" && c.Daemon.Port == 0 {
		return fmt.Errorf("config: port must be set if host is set")
	} else if c.Daemon.Host == "" && c.Daemon.Port != 0 {
		c.Daemon.Host = "localhost"
	} else if strings.HasPrefix(c.Daemon.Socket, "~/") {
		c.Daemon.Socket = filepath.Join(home, c.Daemon.Socket[2:]) // TODO: is this bad practice?
	}
	// verify database
	if c.Database.BatchSize == 0 {
		c.Database.BatchSize = 1000
	}

	return nil
}

// LoadConfig loads the configuration file
func LoadConfig() (*Config, error) {
	c := Config{}

	if len(viper.ConfigFileUsed()) == 0 {
		// NOTE: this is here because if someone doesn't have a config.yml it will ignore the ENV vars
		if err := env.ParseWithOptions(&c, env.Options{Prefix: "IPSW_"}); err != nil {
			return nil, fmt.Errorf("config: failed to parse env vars: %v", err)
		}
	}

	if err := viper.Unmarshal(&c); err != nil {
		return nil, fmt.Errorf("config: failed to unmarshal: %v", err)
	}

	if err := c.verify(); err != nil {
		return nil, fmt.Errorf("config: failed to verify: %v", err)
	}

	return &c, nil
}
