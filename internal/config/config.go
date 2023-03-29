// Package config is used to load the configuration file
package config

import "github.com/spf13/viper"

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
	Database database `json:"database"`
}

// LoadConfig loads the configuration file
func LoadConfig() (*Config, error) {
	var c *Config

	viper.AddConfigPath("./pkg/common/config/envs")
	viper.SetConfigName("dev")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	if err := viper.Unmarshal(&c); err != nil {
		return nil, err
	}

	return c, nil
}
