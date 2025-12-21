/*
Copyright © 2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ipswd",
	Short: "ipsw daemon",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func init() {
	log.SetHandler(clihander.Default)
	cobra.OnInitialize(initConfig)
	// Flags
	var defaultConfg string
	switch runtime.GOOS {
	case "darwin":
		if os.Getenv("IPSW_IN_HOMEBREW") != "" {
			defaultConfg = "/opt/homebrew/etc/ipsw/config.yml"
		} else {
			defaultConfg = filepath.Join("$HOME", ".config", "ipsw", "config.yml")
		}
	case "windows":
		defaultConfg = filepath.Join("$AppData", "ipsw", "config.yml")
	case "linux":
		if os.Getenv("IPSW_IN_SNAP") == "1" {
			defaultConfg = "/root/snap/ipswd/common/ipsw/config.yml"
		} else {
			defaultConfg = "/etc/ipsw/config.yml"
		}
	}
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", fmt.Sprintf("config file (default is %s)", defaultConfg))
	// Settings
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		switch runtime.GOOS {
		case "darwin":
			// Search config in home directory with name ".ipsw" (without extension).
			viper.AddConfigPath(filepath.Join(home, ".config", "ipsw"))
			if os.Getenv("IPSW_IN_HOMEBREW") != "" {
				viper.AddConfigPath("/opt/homebrew/etc/ipsw/config.yaml")
			}
		case "windows":
			dir := os.Getenv("AppData")
			if dir == "" {
				log.Error("init config: %AppData% is not defined")
			}
			// Search config in home directory with name ".ipsw" (without extension).
			viper.AddConfigPath(filepath.Join(dir, "ipsw"))
		case "linux":
			// Search config in home directory with name ".ipsw" (without extension).
			viper.AddConfigPath(filepath.Join("/etc", "ipsw"))
		}
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("ipsw")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.WithField("config", viper.ConfigFileUsed()).Debug("using config file")
	}
}
