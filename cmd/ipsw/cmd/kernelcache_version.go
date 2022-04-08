/*
Copyright © 2022 blacktop

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
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/spf13/cobra"
)

func init() {
	kernelcacheCmd.AddCommand(kernelVersionCmd)
	kernelVersionCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	kernelVersionCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache.*")
	// kernelVersionCmd.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	// 	return []string{"ipsw", "zip"}, cobra.ShellCompDirectiveFilterFileExt
	// }
}

type kernVersion struct {
	Kernel struct {
		Darwin string    `json:"darwin,omitempty"`
		Date   time.Time `json:"date,omitempty"`
		XNU    string    `json:"xnu,omitempty"`
		Type   string    `json:"type,omitempty"`
		Arch   string    `json:"arch,omitempty"`
		CPU    string    `json:"cpu,omitempty"`
	} `json:"kernel,omitempty"`
	LLVM struct {
		Version string   `json:"version,omitempty"`
		Clang   string   `json:"clang,omitempty"`
		Flags   []string `json:"flags,omitempty"`
	} `json:"llvm,omitempty"`
}

// kernelVersionCmd represents the version command
var kernelVersionCmd = &cobra.Command{
	Use:           "version",
	Short:         "Dump kernelcache version",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		asJSON, _ := cmd.Flags().GetBool("json")

		machoPath := filepath.Clean(args[0])

		m, err := macho.Open(machoPath)
		if err != nil {
			return err
		}

		if sec := m.Section("__TEXT", "__const"); sec != nil {
			dat, err := sec.Data()
			if err != nil {
				return fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
			}

			csr := bytes.NewBuffer(dat[:])

			foundKV := false
			foundLLVM := false
			var kv kernVersion

			for {
				pos := sec.Addr + uint64(csr.Cap()-csr.Len())

				s, err := csr.ReadString('\x00')

				if err == io.EOF {
					break
				}

				if err != nil {
					return fmt.Errorf("failed to read string: %v", err)
				}

				s = strings.Trim(s, "\x00")

				if len(s) > 0 {
					if utils.IsASCII(s) {
						if asJSON {
							reKV := regexp.MustCompile(`^Darwin Kernel Version (?P<darwin>.+): (?P<date>.+); root:xnu-(?P<xnu>.+)/(?P<type>.+)_(?P<arch>.+)_(?P<cpu>.+)$`)
							if reKV.MatchString(s) {
								foundKV = true
								matches := reKV.FindStringSubmatch(s)
								kv.Kernel.Darwin = matches[reKV.SubexpIndex("darwin")]
								// TODO: confirm that day is not in form 02 for day
								kv.Kernel.Date, err = time.Parse("Mon Jan 2 15:04:05 MST 2006", matches[reKV.SubexpIndex("date")])
								if err != nil {
									return fmt.Errorf("failed to parse date %s: %v", matches[reKV.SubexpIndex("date")], err)
								}
								kv.Kernel.XNU = matches[reKV.SubexpIndex("xnu")]
								kv.Kernel.Type = matches[reKV.SubexpIndex("type")]
								kv.Kernel.Arch = matches[reKV.SubexpIndex("arch")]
								kv.Kernel.CPU = matches[reKV.SubexpIndex("cpu")]
							}
							reLLVM := regexp.MustCompile(`^Apple LLVM (?P<version>.+) \(clang-(?P<clang>.+)\) \[(?P<flags>.+)\]$`)
							if reLLVM.MatchString(s) {
								foundLLVM = true
								matches := reLLVM.FindStringSubmatch(s)
								kv.LLVM.Version = matches[reLLVM.SubexpIndex("version")]
								kv.LLVM.Clang = matches[reLLVM.SubexpIndex("clang")]
								kv.LLVM.Flags = strings.Split(matches[reLLVM.SubexpIndex("flags")], ", ")
							}
							if foundKV && foundLLVM {
								break
							}
						} else {
							if strings.HasPrefix(s, "Darwin Kernel Version") {
								foundKV = true
								fmt.Printf("%#x: %#v\n", pos, s)
							}
							if strings.HasPrefix(s, "Apple LLVM") {
								foundLLVM = true
								fmt.Printf("%#x: %#v\n", pos, s)
							}
							if foundKV && foundLLVM {
								return nil
							}
						}
					}
				}
			}

			if asJSON {
				if foundKV || foundLLVM {
					o, err := json.Marshal(kv)
					if err != nil {
						return err
					}
					fmt.Println(string(o))
					return nil
				}
			}

		} else {
			return fmt.Errorf("section __TEXT.__const not found in kernelcache (if this is a macOS kernel you might need to first extract the fileset entry)")
		}

		return nil
	},
}
