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
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cache map[string]string

func readAllPlists(inpath string) error {
	return filepath.Walk(inpath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed to walk path: %v", err)
		}
		if filepath.Ext(path) != ".plist" {
			return nil
		}
		if !info.IsDir() {
			settings := make(map[string]any)
			data, err := os.ReadFile(path)
			if err != nil {
				if errors.Is(err, os.ErrPermission) {
					log.Warn(err.Error())
					return nil
				}
				return fmt.Errorf("failed to read plist '%s': %v", path, err)
			}
			if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&settings); err != nil {
				log.Errorf("failed to decode plist '%s': %v", path, err)
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
	rootCmd.AddCommand(defaultsCmd)

	defaultsCmd.Flags().StringP("path", "p", "", "File/Directory to watch (default: $HOME/Library/Preferences)")
	defaultsCmd.Flags().StringSliceP("exclude", "e", []string{
		"ContextStoreAgent.plist",
		"com.apple.knowledge-agent.plist",
		"com.apple.universalaccess.plist"}, "Exclude files/directories")
	viper.BindPFlag("defaults.path", defaultsCmd.Flags().Lookup("path"))
	viper.BindPFlag("defaults.exclude", defaultsCmd.Flags().Lookup("exclude"))

	cache = make(map[string]string)
}

// defaultsCmd represents the defaults command
var defaultsCmd = &cobra.Command{
	Use:           "defaults",
	Aliases:       []string{"defs"},
	Short:         "Watch defaults changes",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		exclude := viper.GetStringSlice("defaults.exclude")

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

		if viper.GetString("defaults.path") != "" {
			path, err := filepath.Abs(viper.GetString("defaults.path"))
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
	},
}
