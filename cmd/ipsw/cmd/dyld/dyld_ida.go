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
package dyld

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/ida"
	"github.com/blacktop/ipsw/internal/commands/ida/dscu"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/caarlos0/ctrlc"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func removeExtension(filename string) string {
	return filename[:len(filename)-len(filepath.Ext(filename))]
}

func init() {
	DyldCmd.AddCommand(idaCmd)

	idaCmd.Flags().StringP("ida-path", "p", "", "IDA Pro directory (darwin default: /Applications/IDA Pro */ida64.app/Contents/MacOS)")
	idaCmd.Flags().StringP("script", "s", "", "IDA Pro script to run")
	idaCmd.Flags().StringSliceP("script-args", "r", []string{}, "IDA Pro script arguments")
	idaCmd.Flags().String("diaphora-db", "", "Path to Diaphora database")
	idaCmd.Flags().BoolP("all", "a", false, "Analyze whole cache (this will take a while)")
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
	idaCmd.Flags().String("docker-entry", "/ida/idat64", "IDA Pro docker entrypoint")
	idaCmd.MarkFlagDirname("output")
	viper.BindPFlag("dyld.ida.ida-path", idaCmd.Flags().Lookup("ida-path"))
	viper.BindPFlag("dyld.ida.script", idaCmd.Flags().Lookup("script"))
	viper.BindPFlag("dyld.ida.script-args", idaCmd.Flags().Lookup("script-args"))
	viper.BindPFlag("dyld.ida.diaphora-db", idaCmd.Flags().Lookup("diaphora-db"))
	viper.BindPFlag("dyld.ida.dependancies", idaCmd.Flags().Lookup("dependancies"))
	viper.BindPFlag("dyld.ida.all", idaCmd.Flags().Lookup("all"))
	viper.BindPFlag("dyld.ida.enable-gui", idaCmd.Flags().Lookup("enable-gui"))
	viper.BindPFlag("dyld.ida.delete-db", idaCmd.Flags().Lookup("delete-db"))
	viper.BindPFlag("dyld.ida.temp-db", idaCmd.Flags().Lookup("temp-db"))
	viper.BindPFlag("dyld.ida.log-file", idaCmd.Flags().Lookup("log-file"))
	viper.BindPFlag("dyld.ida.extra-args", idaCmd.Flags().Lookup("extra-args"))
	viper.BindPFlag("dyld.ida.output", idaCmd.Flags().Lookup("output"))
	viper.BindPFlag("dyld.ida.slide", idaCmd.Flags().Lookup("slide"))
	viper.BindPFlag("dyld.ida.docker", idaCmd.Flags().Lookup("docker"))
	viper.BindPFlag("dyld.ida.docker-image", idaCmd.Flags().Lookup("docker-image"))
	viper.BindPFlag("dyld.ida.docker-entry", idaCmd.Flags().Lookup("docker-entry"))
}

// idaCmd represents the ida command
var idaCmd = &cobra.Command{
	Use:   "ida <DSC> <DYLIB> [DYLIBS...]",
	Short: "Analyze DSC in IDA Pro",
	Args:  cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) != 0 {
			return getImages(args[0]), cobra.ShellCompDirectiveDefault
		}
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var fileType string
		var dbFile string
		var env []string
		var defaultframeworks []string

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		idaProPath := viper.GetString("dyld.ida.ida-path")
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
		} else if viper.IsSet("dyld.ida.diaphora-db") && !viper.IsSet("dyld.ida.script") {
			return fmt.Errorf("must supply '--script /path/to/diaphora.py' with '--diaphora-db /path/to/diaphora.db'")
		} else if (viper.IsSet("dyld.ida.diaphora-db") || strings.Contains(scriptFile, "diaphora.py")) && viper.GetBool("dyld.ida.enable-gui") {
			return fmt.Errorf("diaphora analysis should be done headless and NOT with '--enable-gui'")
		}

		if viper.GetString("dyld.ida.slide") != "" {
			env = append(env, fmt.Sprintf("IDA_DYLD_SHARED_CACHE_SLIDE=%s", viper.GetString("dyld.ida.slide")))
		}

		if !viper.IsSet("dyld.ida.ida-path") {
			switch runtime.GOOS {
			case "darwin":
				matches, err := filepath.Glob(ida.DarwinPathGlob)
				if err != nil {
					return fmt.Errorf("failed to search for IDA Pro: %w", err)
				}
				if len(matches) == 0 {
					return fmt.Errorf("IDA Pro not found: supply IDA Pro path via '--ida-path' (e.g. /Applications/IDA\\ Pro\\ 8.2/ida64.app/Contents/MacOS)")
				}
				if len(matches) == 1 {
					idaProPath = matches[0]
				} else { // len(matches) > 1
					prompt := &survey.Select{
						Message: "Multiple IDA Pro Versions Found:",
						Options: matches,
					}
					if err := survey.AskOne(prompt, &idaProPath); err != nil {
						if err == terminal.InterruptErr {
							log.Warn("Exiting...")
							os.Exit(0)
						}
						return fmt.Errorf("failed to select IDA Pro version: %w", err)
					}
				}
			case "linux":
				// path = linuxPath
				return fmt.Errorf("supply IDA Pro path via '--ida-path' (e.g. /opt/ida-7.0/)")
			case "windows":
				// path = windowsPath
				return fmt.Errorf("supply IDA Pro path via '--ida-path' (e.g. C:\\Program Files\\IDA 7.0)")
			default:
				return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
			}
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

		f, err := dyld.Open(dscPath)
		if err != nil {
			return fmt.Errorf("failed to open dyld shared cache %s: %w", dscPath, err)
		}
		defer f.Close()

		_, magic, ok := strings.Cut(f.Headers[f.UUID].Magic.String(), " ")
		if !ok {
			return fmt.Errorf("failed to get arch from DSC magic %s", f.Headers[f.UUID].Magic.String())
		}

		if viper.GetBool("dyld.ida.all") { // analyze all dylibs
			fileType = fmt.Sprintf(ida.IDAProCompleteImage, strings.TrimSpace(magic))
			dbFile = filepath.Join(folder, fmt.Sprintf("DSC_%s_%s.i64", f.Headers[f.UUID].Platform, f.Headers[f.UUID].OsVersion))
		} else { // analyze single or more dylibs
			if len(args) < 2 {
				return fmt.Errorf("must specify at least one dylib to analyze")
			}
			if strings.Contains(idaProPath, "IDA Professional 9") {
				fileType = fmt.Sprintf(ida.IDPro9SingleModule, strings.TrimSpace(magic))
			} else { // IDA Pro 8 or below
				fileType = fmt.Sprintf(ida.IDAPro8SingleModule, strings.TrimSpace(magic))
			}

			var defaultframeworks = []string{
				"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
				"/System/Library/Frameworks/Foundation.framework/Foundation",
				"/usr/lib/swift/libswiftCore.dylib",
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
				dscuScript, err := dscu.GenerateScript(defaultframeworks, !viper.GetBool("dyld.ida.enable-gui"))
				if err != nil {
					return err
				}
				tmp, err := os.Create(filepath.Join(folder, "dscu.py"))
				if err != nil {
					return err
				}
				objcScripts, err := dscu.ExpandScript()
				if err != nil {
					return err
				}
				if _, err := tmp.WriteString(objcScripts); err != nil {
					return err
				}
				if _, err := tmp.WriteString(dscuScript); err != nil {
					return err
				}
				if err := tmp.Close(); err != nil {
					return err
				}
				scriptFile = tmp.Name()
				defer os.Remove(scriptFile)
			}

			env = append(env, fmt.Sprintf("IDA_DYLD_CACHE_MODULE=%s", img.Name))

			dbFile = filepath.Join(folder, fmt.Sprintf("DSC_%s_%s_%s.i64", filepath.Base(img.Name), f.Headers[f.UUID].Platform, f.Headers[f.UUID].OsVersion))
		}

		if viper.IsSet("dyld.ida.diaphora-db") || strings.Contains(scriptFile, "diaphora.py") {
			env = append(env, "DIAPHORA_AUTO=1")
			env = append(env, "DIAPHORA_USE_DECOMPILER=1")
			env = append(env, fmt.Sprintf("DIAPHORA_CPU_COUNT=%d", runtime.NumCPU()))
			if viper.IsSet("dyld.ida.diaphora-db") {
				env = append(env, fmt.Sprintf("DIAPHORA_EXPORT_FILE=%s", viper.GetString("dyld.ida.diaphora-db")))
			} else {
				env = append(env, fmt.Sprintf("DIAPHORA_EXPORT_FILE=%s", filepath.Join(folder, fmt.Sprintf("DSC_%s_%s_%s_diaphora.db", filepath.Base(args[1]), f.Headers[f.UUID].Platform, f.Headers[f.UUID].OsVersion))))
			}
			if viper.GetBool("verbose") {
				env = append(env, "DIAPHORA_DEBUG=1")
				env = append(env, "DIAPHORA_LOG_PRINT=1")
			}
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
			IdaPath:      idaProPath,
			InputFile:    dscPath,
			Frameworks:   defaultframeworks,
			LogFile:      logFile,
			Output:       dbFile,
			EnableGUI:    viper.GetBool("dyld.ida.enable-gui"),
			TempDatabase: viper.GetBool("dyld.ida.temp-db"), // TODO: I think this is actually useless
			DeleteDB:     viper.GetBool("dyld.ida.delete-db"),
			CompressDB:   true,
			FileType:     fileType,
			AutoAnalyze:  true,
			Env:          env,
			Options:      []string{"objc:+l"},
			ScriptFile:   scriptFile,
			ScriptArgs:   viper.GetStringSlice("dyld.ida.script-args"),
			ExtraArgs:    viper.GetStringSlice("dyld.ida.extra-args"),
			// RemoteDebugger: ida.RemoteDebugger{
			// 	Host: viper.GetString("remote-debugger-host"),
			// 	Port: viper.GetInt("remote-debugger-port"),
			// },
			Verbose:     viper.GetBool("verbose"),
			RunInDocker: viper.GetBool("dyld.ida.docker"),
			DockerImage: viper.GetString("dyld.ida.docker-image"),
			DockerEntry: viper.GetString("dyld.ida.docker-entry"),
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
			return cli.Run()
		}); err != nil {
			if errors.As(err, &ctrlc.ErrorCtrlC{}) {
				log.Warn("Exiting...")
				return cli.Stop()
			}
			return fmt.Errorf("failed to run IDA Pro: %v", err)
		}

		if !viper.GetBool("dyld.ida.temp-db") {
			cwd, _ := os.Getwd()
			log.WithField("db", strings.TrimPrefix(dbFile, cwd)).Info("🎉 Done!")
		}

		return nil
	},
}
