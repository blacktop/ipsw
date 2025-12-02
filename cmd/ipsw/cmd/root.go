/*
Copyright © 2018-2025 blacktop

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
	"strings"

	"github.com/apex/log"
	clihander "github.com/apex/log/handlers/cli"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/appstore"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/disk"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/download"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/dyld"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/frida"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/fw"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/idev"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/img3"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/img4"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/kernel"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/macho"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/ota"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/sb"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/ssh"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	// Verbose boolean flag for verbose logging
	Verbose bool
	// AppVersion stores the plugin's version
	AppVersion string
	// AppBuildCommit stores the plugin's build commit
	AppBuildCommit string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ipsw",
	Short: "Download and Parse IPSWs (and SO much more)",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		colors.Init()
	},
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

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// Flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/ipsw/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "V", false, "verbose output")
	rootCmd.PersistentFlags().Bool("color", false, "colorize output")
	rootCmd.PersistentFlags().Bool("no-color", false, "disable colorize output")
	rootCmd.PersistentFlags().String("diff-tool", "", "git diff tool (for --diff commands)")
	rootCmd.PersistentFlags().MarkHidden("diff-tool")
	rootCmd.PersistentFlags().Bool("config-quiet", false, "silence config file loading message")
	rootCmd.PersistentFlags().MarkHidden("config-quiet")
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("color", rootCmd.PersistentFlags().Lookup("color"))
	viper.BindPFlag("no-color", rootCmd.PersistentFlags().Lookup("no-color"))
	viper.BindPFlag("diff-tool", rootCmd.PersistentFlags().Lookup("diff-tool"))
	viper.BindPFlag("config-quiet", rootCmd.PersistentFlags().Lookup("config-quiet"))
	viper.BindEnv("color", "CLICOLOR")
	viper.BindEnv("no-color", "NO_COLOR")
	// Add subcommand groups
	rootCmd.AddCommand(appstore.AppstoreCmd)
	rootCmd.AddCommand(disk.DiskCmd)
	rootCmd.AddCommand(download.DownloadCmd)
	rootCmd.AddCommand(dyld.DyldCmd)
	rootCmd.AddCommand(frida.FridaCmd)
	rootCmd.AddCommand(fw.FwCmd)
	rootCmd.AddCommand(idev.IDevCmd)
	rootCmd.AddCommand(img3.Img3Cmd)
	rootCmd.AddCommand(img4.Img4Cmd)
	rootCmd.AddCommand(kernel.KernelcacheCmd)
	rootCmd.AddCommand(macho.MachoCmd)
	rootCmd.AddCommand(ota.OtaCmd)
	rootCmd.AddCommand(sb.SbCmd)
	rootCmd.AddCommand(ssh.SSHCmd)
	// Settings
	rootCmd.CompletionOptions.HiddenDefaultCmd = true
}

// expandPath expands tilde (~) and relative (./) paths
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return path // return original path if we can't get home dir
		}
		return filepath.Join(home, path[2:])
	}

	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return home
	}

	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		abs, err := filepath.Abs(path)
		if err != nil {
			return path // return original if we can't resolve
		}
		return abs
	}

	return path
}

// expandConfigPaths expands relative and tilde paths in all config values
func expandConfigPaths() {
	allSettings := viper.AllSettings()
	expandSettings(allSettings, "")

	// Merge the expanded settings back into viper
	for key, value := range allSettings {
		viper.Set(key, value)
	}
}

// expandSettings recursively processes all configuration values and expands relative paths
func expandSettings(settings map[string]any, prefix string) {
	for key, value := range settings {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case string:
			if needsExpansion(v) {
				expanded := expandPath(v)
				if expanded != v {
					log.Warnf("Expanded config path %s: %s → %s (use full paths to avoid warnings)", fullKey, v, expanded)
				}
				settings[key] = expanded
			}
		case map[string]any:
			expandSettings(v, fullKey)
		case []any:
			for i, item := range v {
				if str, ok := item.(string); ok && needsExpansion(str) {
					expanded := expandPath(str)
					if expanded != str {
						log.Warnf("Expanded config path %s[%d]: %s → %s (use full paths to avoid warnings)", fullKey, i, str, expanded)
					}
					v[i] = expanded
				}
			}
		}
	}
}

// needsExpansion checks if a string looks like a relative path that should be expanded
func needsExpansion(s string) bool {
	return strings.HasPrefix(s, "~/") || s == "~" || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
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

		// Search config in home directory with name ".ipsw" (without extension).
		viper.AddConfigPath(filepath.Join(home, ".config", "ipsw"))
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.SetEnvPrefix("ipsw")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if !viper.GetBool("config-quiet") {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}

		// Expand tilde paths in the loaded configuration
		expandConfigPaths()
	}
}
