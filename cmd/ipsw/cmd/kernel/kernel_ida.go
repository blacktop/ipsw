/*
Copyright © 2023 blacktop

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
package kernel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/commands/ida"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/caarlos0/ctrlc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
// "Apple XNU kernelcache for ARM64e (kernel + all kexts)"
// "Apple XNU kernelcache for ARM64e (kernel only)"
// "Apple XNU kernelcache for ARM64e (single kext)"
// "Apple XNU kernelcache for ARM64e (normal mach-o file)"
)

func removeExtension(filename string) string {
	return filename[:len(filename)-len(filepath.Ext(filename))]
}

func init() {
	KernelcacheCmd.AddCommand(idaCmd)

	idaCmd.Flags().StringP("ida-path", "p", "", "IDA Pro directory (darwin default: /Applications/IDA Pro */ida64.app/Contents/MacOS)")
	idaCmd.Flags().StringP("script", "s", "", "IDA Pro script to run")
	idaCmd.Flags().StringSliceP("script-args", "r", []string{}, "IDA Pro script arguments")
	idaCmd.Flags().BoolP("all", "a", false, "Analyze kernel+kexts (this will take a while)")
	idaCmd.Flags().BoolP("enable-gui", "g", false, "Enable IDA Pro GUI (defaults to headless)")
	idaCmd.Flags().BoolP("delete-db", "c", false, "Disassemble a new file (delete the old database)")
	idaCmd.Flags().BoolP("temp-db", "t", false, "Do not create a database file (requires --enable-gui)")
	idaCmd.Flags().StringP("log-file", "l", "", "IDA log file")
	idaCmd.Flags().StringSliceP("extra-args", "e", []string{}, "IDA Pro CLI extra arguments")
	idaCmd.Flags().StringP("output", "o", "", "Output folder")
	// idaCmd.Flags().String("slide", "", "kernelcache ASLR slide value (hexadecimal)")
	idaCmd.Flags().BoolP("docker", "k", false, "Run IDA Pro in a docker container")
	idaCmd.Flags().String("docker-image", "blacktop/idapro:8.2-pro", "IDA Pro docker image")
	viper.BindPFlag("dyld.ida.ida-path", idaCmd.Flags().Lookup("ida-path"))
	viper.BindPFlag("dyld.ida.script", idaCmd.Flags().Lookup("script"))
	viper.BindPFlag("dyld.ida.script-args", idaCmd.Flags().Lookup("script-args"))
	viper.BindPFlag("dyld.ida.all", idaCmd.Flags().Lookup("all"))
	viper.BindPFlag("dyld.ida.enable-gui", idaCmd.Flags().Lookup("enable-gui"))
	viper.BindPFlag("dyld.ida.delete-db", idaCmd.Flags().Lookup("delete-db"))
	viper.BindPFlag("dyld.ida.temp-db", idaCmd.Flags().Lookup("temp-db"))
	viper.BindPFlag("dyld.ida.log-file", idaCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("dyld.ida.extra-args", idaCmd.Flags().Lookup("extra-args"))
	viper.BindPFlag("dyld.ida.output", idaCmd.Flags().Lookup("output"))
	// viper.BindPFlag("dyld.ida.slide", idaCmd.Flags().Lookup("slide"))
	viper.BindPFlag("dyld.ida.docker", idaCmd.Flags().Lookup("docker"))
	viper.BindPFlag("dyld.ida.docker-image", idaCmd.Flags().Lookup("docker-image"))
}

// idaCmd represents the ida command
var idaCmd = &cobra.Command{
	Use:           "ida <KC> <KEXT> [KEXTS...]",
	Short:         "🚧 Analyze kernelcache in IDA Pro",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		var fileType string
		var dbFile string
		var env []string
		var autoAnalyze bool
		var defaultframeworks []string

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		scriptFile := viper.GetString("dyld.ida.script")
		logFile := viper.GetString("dyld.ida.log-file")
		output := viper.GetString("dyld.ida.output")
		// validate args
		if !viper.GetBool("dyld.ida.enable-gui") && viper.GetBool("dyld.ida.temp-db") {
			return fmt.Errorf("cannot use '--temp-db' without '--enable-gui'")
		} else if viper.GetBool("dyld.ida.temp-db") && viper.GetBool("dyld.ida.delete-db") {
			return fmt.Errorf("cannot use '--temp-db' and '--delete-db'")
		} else if len(args) > 2 && viper.GetBool("dyld.ida.dependancies") {
			log.Warnf("will only load dependancies for first dylib (%s)", args[1])
		}

		// if viper.GetString("dyld.ida.slide") != "" { TODO: how to set kc slide?
		// 	env = append(env, fmt.Sprintf("IDA_DYLD_SHARED_CACHE_SLIDE=%s", viper.GetString("dyld.ida.slide")))
		// }

		kcPath, err := filepath.Abs(filepath.Clean(args[0]))
		if err != nil {
			return errors.Wrapf(err, "failed to get absolute path for %s", kcPath)
		}

		folder := filepath.Dir(kcPath) // default to folder of kernelcache
		if len(output) > 0 {
			absout, err := filepath.Abs(output)
			if err != nil {
				return fmt.Errorf("failed to get absolute path of %s: %w", output, err)
			}
			folder = absout
		} else {
			if viper.GetBool("dyld.ida.temp-db") {
				folder = os.TempDir()
			}
		}
		if _, err := os.Stat(folder); os.IsPermission(err) {
			log.Errorf("permission denied to write to %s", folder)
			log.Warn("will attempt to write to current directory")
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current working directory: %w", err)
			}
			folder = cwd
		} else if os.IsNotExist(err) {
			if err := os.MkdirAll(folder, 0755); err != nil {
				return fmt.Errorf("failed to create folder %s: %w", folder, err)
			}
		}

		m, err := macho.Open(kcPath)
		if err != nil {
			return fmt.Errorf("failed to open kernelcache %s: %w", kcPath, err)
		}
		defer m.Close()

		if viper.GetBool("dyld.ida.all") { // analyze all dylibs
			autoAnalyze = true
			device := filepath.Ext(kcPath)[1:]
			fileType = fmt.Sprintf("Apple XNU kernelcache for %s (kernel + all kexts)", m.SubCPU.String(m.CPU))
			dbFile = filepath.Join(folder, fmt.Sprintf("KC_%s_%s.i64", device, m.SubCPU.String(m.CPU)))
		} else { // analyze single or more dylibs
			return fmt.Errorf("single kext support not implemented yet (please use --all)")
		}

		if len(logFile) > 0 {
			logFile = filepath.Join(folder, viper.GetString("dyld.ida.log-file"))
			if _, err := os.Stat(logFile); err == nil {
				if err := os.Remove(logFile); err != nil {
					return fmt.Errorf("failed to remove log file %s: %w", logFile, err)
				}
			}
		}

		if viper.GetBool("dyld.ida.temp-db") { // clean up temp IDA database files
			defer func() {
				matches, err := filepath.Glob(removeExtension(dbFile) + ".*")
				if err != nil {
					log.Errorf("failed to get temp IDA database files: %v", err)
					return
				}
				for _, match := range matches {
					utils.Indent(log.Info, 2)(fmt.Sprintf("deleting temp IDA database %s", match))
					os.Remove(match)
				}
			}()
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		cli, err := ida.NewClient(ctx, &ida.Config{
			IdaPath:      viper.GetString("dyld.ida.ida-path"),
			InputFile:    kcPath,
			Frameworks:   defaultframeworks,
			LogFile:      logFile,
			Output:       dbFile,
			EnableGUI:    viper.GetBool("dyld.ida.enable-gui"),
			TempDatabase: viper.GetBool("dyld.ida.temp-db"), // TODO: I think this is actually useless
			DeleteDB:     viper.GetBool("dyld.ida.delete-db"),
			CompressDB:   true,
			FileType:     fileType,
			AutoAnalyze:  autoAnalyze,
			Env:          env,
			// Options:      []string{"objc:+l"},
			ScriptFile: scriptFile,
			ScriptArgs: viper.GetStringSlice("dyld.ida.script-args"),
			ExtraArgs:  viper.GetStringSlice("dyld.ida.extra-args"),
			// RemoteDebugger: ida.RemoteDebugger{
			// 	Host: viper.GetString("remote-debugger-host"),
			// 	Port: viper.GetInt("remote-debugger-port"),
			// },
			Verbose:     viper.GetBool("verbose"),
			RunInDocker: viper.GetBool("dyld.ida.docker"),
			DockerImage: viper.GetString("dyld.ida.docker-image"),
		})
		if err != nil {
			return err
		}

		m.Close() // close the kernelcache file so IDA can open it

		if err := ctrlc.Default.Run(ctx, func() error {
			if viper.GetBool("dyld.ida.docker") {
				log.Info("Starting IDA Pro in Docker...")
			} else {
				log.Info("Starting IDA Pro...")
			}
			if err := cli.Run(); err != nil {
				return err
			}
			return nil
		}); err != nil {
			if errors.As(err, &ctrlc.ErrorCtrlC{}) {
				log.Warn("Exiting...")
				return cli.Stop()
			}
			return fmt.Errorf("failed to run IDA Pro: %v", err)
		}

		if !viper.GetBool("dyld.ida.temp-db") {
			log.WithField("db", dbFile).Info("🎉 Done!")
		}

		return nil
	},
}
