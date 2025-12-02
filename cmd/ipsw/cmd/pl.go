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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cache map[string]string

func readAllPlists(inpath string) error {
	return filepath.Walk(inpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorf("failed to walk path: %v", err)
			return nil
		}
		if filepath.Ext(path) != ".plist" {
			return nil
		}
		if !info.IsDir() {
			settings := make(map[string]any)
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, os.ErrPermission) {
					log.Debug(err.Error())
					return nil
				}
				return fmt.Errorf("failed to read plist '%s': %v", path, err)
			}
			if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&settings); err != nil {
				log.Debugf("failed to decode plist '%s': %v", path, err)
				return nil
			}
			jdata, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal json: %v", err)
			}
			cache[path] = string(jdata)
		}
		return nil
	})
}

func init() {
	rootCmd.AddCommand(plistCmd)

	plistCmd.Flags().BoolP("watch", "w", false, "Watch file/Directory (default: $HOME/Library/Preferences)")
	plistCmd.Flags().StringSliceP("exclude", "e", []string{
		"ContextStoreAgent.plist",
		"com.apple.knowledge-agent.plist",
		"com.apple.universalaccess.plist"}, "Exclude files/directories from watching")
	viper.BindPFlag("plist.watch", plistCmd.Flags().Lookup("watch"))
	viper.BindPFlag("plist.exclude", plistCmd.Flags().Lookup("exclude"))

	cache = make(map[string]string)
}

// plistCmd represents the pl command
var plistCmd = &cobra.Command{
	Use:           "plist <file|watch-path>",
	Aliases:       []string{"pl"},
	Short:         "Dump plist as JSON",
	Args:          cobra.MaximumNArgs(1),
	SilenceErrors: true,
	Example: heredoc.Doc(`
		# Convert a plist file to JSON
		$ ipsw plist Info.plist

		# Pipe JSON to jq
		$ ipsw plist Info.plist --no-color | jq .

		# Read plist from stdin
		$ cat Info.plist | ipsw plist

		# Watch a directory for plist changes
		$ ipsw plist --watch ~/Library/Preferences

		# Watch a specific directory and exclude certain files
		$ ipsw plist --watch /System/Library/LaunchDaemons --exclude "com.apple.*.plist"
	`),
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetBool("plist.watch") { // watch mode
			exclude := viper.GetStringSlice("plist.exclude")

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				return err
			}
			defer watcher.Close()

			go func() {
				for {
					select {
					case event, ok := <-watcher.Events:
						if !ok {
							return
						}
						if utils.StrContainsStrSliceItem(event.Name, exclude) {
							continue
						}
						if event.Has(fsnotify.Create) {
							continue
						}
						log.Infof("event: %s", event.String())

						settings := make(map[string]any)
						data, err := os.ReadFile(event.Name)
						if err != nil {
							log.Fatal(err.Error())
						}
						if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&settings); err != nil {
							log.Fatal(err.Error())
						}
						jdata, err := json.MarshalIndent(settings, "", "  ")
						if err != nil {
							log.Fatal(err.Error())
						}

						if prev, ok := cache[event.Name]; ok {
							out, err := utils.GitDiff(prev+"\n", string(jdata)+"\n", &utils.GitDiffConfig{Color: true})
							if err != nil {
								log.Fatal(err.Error())
							}
							fmt.Println(out)
							cache[event.Name] = string(jdata)
						} else {
							cache[event.Name] = string(jdata)
						}
					case err, ok := <-watcher.Errors:
						if !ok {
							return
						}
						log.Errorf("error: %v", err)
					}
				}
			}()

			if len(args) > 0 {
				path, err := filepath.Abs(args[0])
				if err != nil {
					return err
				}
				if err := readAllPlists(path); err != nil {
					return err
				}
				if err := watcher.Add(path); err != nil {
					return err
				}
			} else {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("failed to get user home directory: %v", err)
				}
				if err := readAllPlists(filepath.Join(home, "Library/Preferences")); err != nil {
					return err
				}
				if err := watcher.Add(filepath.Join(home, "Library/Preferences")); err != nil {
					return err
				}
			}

			log.Info("Watching for defaults changes...")

			<-ctx.Done()

			return watcher.Close()
		}

		// print mode
		var data []byte
		if len(args) > 0 {
			data, err = os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read plist: %v", err)
			}
		} else {
			// Read from stdin
			stat, err := os.Stdin.Stat()
			if err != nil {
				return fmt.Errorf("failed to read from stdin: %v", err)
			}
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				data, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %v", err)
				}
			} else {
				return fmt.Errorf("no input provided via stdin")
			}
		}

		var out map[string]any
		if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&out); err != nil {
			return fmt.Errorf("failed to decode plist: %v", err)
		}

		jsonData, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal json: %v", err)
		}

		if colors.Active() {
			if err := quick.Highlight(os.Stdout, string(jsonData)+"\n", "json", "terminal256", "nord"); err != nil {
				return fmt.Errorf("failed to highlight json: %v", err)
			}
		} else {
			fmt.Println(string(jsonData))
		}

		return nil
	},
}
