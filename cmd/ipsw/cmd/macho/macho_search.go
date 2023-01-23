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
package macho

import (
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoSearchCmd)
	machoSearchCmd.Flags().StringP("ipsw", "i", "", "Path to IPSW to scan for search criteria")
	machoSearchCmd.Flags().StringP("load-command", "l", "", "Search for specific load command")
	machoSearchCmd.Flags().StringP("protocol", "p", "", "Search for specific ObjC protocol")
	machoSearchCmd.Flags().StringP("class", "c", "", "Search for specific ObjC class")
	machoSearchCmd.Flags().StringP("category", "g", "", "Search for specific ObjC category")
	viper.BindPFlag("macho.search.ipsw", machoSearchCmd.Flags().Lookup("ipsw"))
	viper.BindPFlag("macho.search.load-command", machoSearchCmd.Flags().Lookup("load-command"))
	viper.BindPFlag("macho.search.protocol", machoSearchCmd.Flags().Lookup("protocol"))
	viper.BindPFlag("macho.search.class", machoSearchCmd.Flags().Lookup("class"))
	viper.BindPFlag("macho.search.category", machoSearchCmd.Flags().Lookup("category"))
}

// machoSearchCmd represents the search command
var machoSearchCmd = &cobra.Command{
	Use:     "search",
	Aliases: []string{"sr"},
	Short:   "Create single universal/fat MachO out many MachOs",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if viper.GetString("macho.search.ipsw") != "" {
			if err := search.ForEachMachoInIPSW(filepath.Clean(viper.GetString("macho.search.ipsw")), func(path string, m *macho.File) error {
				if viper.GetString("macho.search.load-command") != "" {
					for _, lc := range m.Loads {
						if lc.Command().String() == viper.GetString("macho.search.load-command") {
							fmt.Println(path)
							break
						}
					}
				}
				if m.HasObjC() {
					if viper.GetString("macho.search.protocol") != "" {
						if protos, err := m.GetObjCProtocols(); err == nil {
							for _, proto := range protos {
								if proto.Name == viper.GetString("macho.search.protocol") {
									fmt.Println(path)
									break
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
					}
					if viper.GetString("macho.search.class") != "" {
						if classes, err := m.GetObjCClasses(); err == nil {
							for _, class := range classes {
								if class.Name == viper.GetString("macho.search.class") {
									fmt.Println(path)
									break
								}
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
					}
				}
				if viper.GetString("macho.search.category") != "" {
					if cats, err := m.GetObjCCategories(); err == nil {
						for _, cat := range cats {
							if cat.Name == viper.GetString("macho.search.category") {
								fmt.Println(path)
								break
							}
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to scan files in IPSW: %v", err)
			}
		}

		return nil
	},
}
