/*
Copyright © 2018-2023 blacktop

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
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/download"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/dyld"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/frida"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/idev"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/img4"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/kernel"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/macho"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/ota"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/sb"
	"github.com/blacktop/ipsw/cmd/ipsw/cmd/ssh"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	// Verbose boolean flag for verbose logging
	Verbose bool
	// Color boolean flag for colorized output
	Color bool
	// AppVersion stores the plugin's version
	AppVersion string
	// AppBuildTime stores the plugin's build time
	AppBuildTime string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ipsw",
	Short: "Download and Parse IPSWs (and SO much more)",
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
	rootCmd.PersistentFlags().BoolVar(&Color, "color", false, "colorize output")
	rootCmd.PersistentFlags().String("diff-tool", "", "git diff tool (for --diff commands)")
	rootCmd.PersistentFlags().MarkHidden("diff-tool")
	viper.BindPFlag("verbose", rootCmd.Flags().Lookup("verbose"))
	viper.BindPFlag("color", rootCmd.Flags().Lookup("color"))
	viper.BindPFlag("diff-tool", rootCmd.Flags().Lookup("diff-tool"))
	viper.BindEnv("color", "CLICOLOR")
	// Add subcommand groups
	rootCmd.AddCommand(appstore.AppstoreCmd)
	rootCmd.AddCommand(download.DownloadCmd)
	rootCmd.AddCommand(dyld.DyldCmd)
	rootCmd.AddCommand(frida.FridaCmd)
	rootCmd.AddCommand(idev.IDevCmd)
	rootCmd.AddCommand(img4.Img4Cmd)
	rootCmd.AddCommand(kernel.KernelcacheCmd)
	rootCmd.AddCommand(macho.MachoCmd)
	rootCmd.AddCommand(ota.OtaCmd)
	rootCmd.AddCommand(sb.SbCmd)
	rootCmd.AddCommand(ssh.SSHCmd)
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
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
