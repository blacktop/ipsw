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
package dyld

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/ida"
	"github.com/blacktop/ipsw/internal/commands/ida/dscu"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/caarlos0/ctrlc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(idaCmd)

	idaCmd.Flags().StringP("ida-path", "p", "", "IDA Pro directory (darwin default: /Applications/IDA Pro */ida64.app/Contents/MacOS)")
	idaCmd.Flags().StringP("script", "s", "", "IDA Pro script to run")
	idaCmd.Flags().StringSliceP("script-args", "a", []string{}, "IDA Pro script arguments")
	idaCmd.Flags().BoolP("dependancies", "d", false, "Analyze module dependencies")
	idaCmd.Flags().BoolP("enable-gui", "g", false, "Enable IDA Pro GUI (defaults to headless)")
	idaCmd.Flags().BoolP("delete-db", "c", false, "Disassemble a new file (delete the old database)")
	idaCmd.Flags().BoolP("temp-db", "t", false, "Do not create a database file (requires --enable-gui)")
	idaCmd.Flags().StringP("log-file", "l", "", "IDA log file")
	idaCmd.Flags().StringSliceP("extra-args", "e", []string{}, "IDA Pro CLI extra arguments")
	idaCmd.Flags().StringP("output", "o", "", "Output folder")
	idaCmd.Flags().String("slide", "", "dyld_shared_cache image ASLR slide value (hexadecimal)")
	idaCmd.Flags().BoolP("docker", "k", false, "Run IDA Pro in a docker container")
	idaCmd.Flags().String("docker-image", "blacktop/idapro:8.2-pro", "IDA Pro docker image")
	viper.BindPFlag("dyld.ida.ida-path", idaCmd.Flags().Lookup("ida-path"))
	viper.BindPFlag("dyld.ida.script", idaCmd.Flags().Lookup("script"))
	viper.BindPFlag("dyld.ida.script-args", idaCmd.Flags().Lookup("script-args"))
	viper.BindPFlag("dyld.ida.dependancies", idaCmd.Flags().Lookup("dependancies"))
	viper.BindPFlag("dyld.ida.enable-gui", idaCmd.Flags().Lookup("enable-gui"))
	viper.BindPFlag("dyld.ida.delete-db", idaCmd.Flags().Lookup("delete-db"))
	viper.BindPFlag("dyld.ida.temp-db", idaCmd.Flags().Lookup("temp-db"))
	viper.BindPFlag("dyld.ida.log-file", idaCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("dyld.ida.extra-args", idaCmd.Flags().Lookup("extra-args"))
	viper.BindPFlag("dyld.ida.output", idaCmd.Flags().Lookup("output"))
	viper.BindPFlag("dyld.ida.slide", idaCmd.Flags().Lookup("slide"))
	viper.BindPFlag("dyld.ida.docker", idaCmd.Flags().Lookup("docker"))
	viper.BindPFlag("dyld.ida.docker-image", idaCmd.Flags().Lookup("docker-image"))
}

// idaCmd represents the ida command
var idaCmd = &cobra.Command{
	Use:           "ida <DSC> <DYLIB> [DYLIBS...]",
	Short:         "Analyze DSC in IDA Pro",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
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

		dscPath, err := filepath.Abs(filepath.Clean(args[0]))
		if err != nil {
			return errors.Wrapf(err, "failed to get absolute path for %s", dscPath)
		}

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		folder := filepath.Dir(dscPath) // default to folder of shared cache
		if len(output) > 0 {
			absout, err := filepath.Abs(output)
			if err != nil {
				return fmt.Errorf("failed to get absolute path of %s: %w", output, err)
			}
			folder = absout
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

		f, err := dyld.Open(dscPath)
		if err != nil {
			return fmt.Errorf("failed to open dyld shared cache %s: %w", dscPath, err)
		}

		var defaultframeworks = []string{
			"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
			"/System/Library/Frameworks/Foundation.framework/Foundation",
			"/usr/lib/libobjc.A.dylib",
			"/usr/lib/system/libdyld.dylib",
			"/usr/lib/system/libsystem_blocks.dylib",
			"/usr/lib/system/libsystem_c.dylib",
			"/usr/lib/system/libsystem_darwin.dylib",
			"/usr/lib/system/libsystem_kernel.dylib",
			"/usr/lib/system/libsystem_platform.dylib",
			"/usr/lib/system/libsystem_trace.dylib",
			"/usr/lib/system/libunwind.dylib",
		}

		if len(args) > 2 { // add any extra args to default frameworks
			for _, additional := range args[2:] {
				img, err := f.Image(additional)
				if err != nil {
					return fmt.Errorf("failed to get image %s: %w", additional, err)
				}
				defaultframeworks = append(defaultframeworks, img.Name)
			}
		}

		img, err := f.Image(args[1])
		if err != nil {
			return fmt.Errorf("failed to get image %s: %w", args[1], err)
		}

		if viper.GetBool("dyld.ida.dependancies") {
			m, err := img.GetMacho()
			if err != nil {
				return fmt.Errorf("failed to get macho for %s: %w", img.Name, err)
			}
			defaultframeworks = append(defaultframeworks, m.ImportedLibraries()...)
		}

		if scriptFile == "" {
			script, err := dscu.GenerateScript(defaultframeworks, !viper.GetBool("dyld.ida.enable-gui"))
			if err != nil {
				return err
			}
			tmp, err := os.Create(filepath.Join(folder, "dscu.py"))
			if err != nil {
				return err
			}
			if _, err := tmp.WriteString(script); err != nil {
				return err
			}
			if err := tmp.Close(); err != nil {
				return err
			}
			scriptFile = tmp.Name()
			defer os.Remove(scriptFile)
		}

		if len(logFile) > 0 {
			logFile = filepath.Join(folder, viper.GetString("dyld.ida.log-file"))
			if _, err := os.Stat(logFile); err == nil {
				if err := os.Remove(logFile); err != nil {
					return fmt.Errorf("failed to remove log file %s: %w", logFile, err)
				}
			}
		}

		dbFile := filepath.Join(folder, fmt.Sprintf("DSC_%s_%s_%s.i64", args[1], f.Headers[f.UUID].Platform, f.Headers[f.UUID].OsVersion))

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		_, magic, ok := strings.Cut(f.Headers[f.UUID].Magic.String(), " ")
		if !ok {
			return fmt.Errorf("failed to get arch from DSC magic %s", f.Headers[f.UUID].Magic.String())
		}

		cli, err := ida.NewClient(ctx, &ida.Config{
			IdaPath:      viper.GetString("dyld.ida.ida-path"),
			InputFile:    dscPath,
			Frameworks:   defaultframeworks,
			LogFile:      logFile,
			Output:       dbFile,
			EnableGUI:    viper.GetBool("dyld.ida.enable-gui"),
			TempDatabase: viper.GetBool("dyld.ida.temp-database"),
			DeleteDB:     viper.GetBool("dyld.ida.delete-db"),
			CompressDB:   true,
			FileType:     fmt.Sprintf("Apple DYLD cache for %s (single module)", strings.TrimSpace(magic)),
			Env: []string{
				fmt.Sprintf("IDA_DYLD_CACHE_MODULE=%s", img.Name),
				fmt.Sprintf("IDA_DYLD_SHARED_CACHE_SLIDE=%s", viper.GetString("dyld.ida.slide")),
			},
			Options:    []string{"objc:+l"},
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

		f.Close() // close the dyld_shared_cache file so IDA can open it

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
			var cerr *ctrlc.ErrorCtrlC
			if errors.As(err, &cerr) {
				log.Warn("Exiting...")
				os.Exit(0)
			} else {
				return fmt.Errorf("failed to run IDA Pro: %v", err)
			}
		}

		log.WithField("db", dbFile).Info("🎉 Done!")

		return nil
	},
}
