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
package dyld

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(StrSearchCmd)
	StrSearchCmd.Flags().BoolP("insensitive", "i", false, "Case-insensitive search")
	StrSearchCmd.Flags().BoolP("contains", "c", false, "Match strings that contain the search substring")
	StrSearchCmd.Flags().StringP("pattern", "p", "", "Regex match strings (FAST)")
	viper.BindPFlag("dyld.str.insensitive", StrSearchCmd.Flags().Lookup("insensitive"))
	viper.BindPFlag("dyld.str.contains", StrSearchCmd.Flags().Lookup("contains"))
	viper.BindPFlag("dyld.str.pattern", StrSearchCmd.Flags().Lookup("pattern"))
}

// StrSearchCmd represents the str command
var StrSearchCmd = &cobra.Command{
	Use:   "str <dyld_shared_cache> <string>",
	Short: "Search dyld_shared_cache for string",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		var err error
		var strRE *regexp.Regexp

		insensitive := viper.GetBool("dyld.str.insensitive")
		contains := viper.GetBool("dyld.str.contains")
		pattern := viper.GetString("dyld.str.pattern")

		if len(pattern) > 0 {
			strRE, err = regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regex: %w", err)
			}
		}

		dscPath := filepath.Clean(args[0])

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

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		for _, i := range f.Images {
			log.Debugf("Searching image %s", i.Name)
			m, err := i.GetMacho()
			if err != nil {
				return err
			}

			// cstrings
			for _, sec := range m.Sections {
				if sec.Flags.IsCstringLiterals() || sec.Seg == "__TEXT" && sec.Name == "__const" {
					uuid, off, err := f.GetOffset(sec.Addr)
					if err != nil {
						return fmt.Errorf("failed to get offset for %s.%s: %v", sec.Seg, sec.Name, err)
					}
					dat, err := f.ReadBytesForUUID(uuid, int64(off), sec.Size)
					if err != nil {
						return fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
					}

					csr := bytes.NewBuffer(dat)

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
							if (sec.Seg == "__TEXT" && sec.Name == "__const") && !utils.IsASCII(s) {
								continue // skip non-ascii strings when dumping __TEXT.__const
							}
							if len(pattern) > 0 {
								if strRE.MatchString(s) {
									fmt.Printf("%#x: (%s)\t%#v\n", pos, filepath.Base(i.Name), s)
								}
							} else {
								if contains && insensitive {
									if strings.Contains(strings.ToLower(s), strings.ToLower(args[1])) {
										fmt.Printf("%#x: (%s)\t%#v\n", pos, filepath.Base(i.Name), s)
									}
								} else if contains {
									if strings.Contains(s, args[1]) {
										fmt.Printf("%#x: (%s)\t%#v\n", pos, filepath.Base(i.Name), s)
									}
								} else if insensitive {
									if len(s) == len(args[1]) && strings.EqualFold(s, args[1]) {
										fmt.Printf("%#x: (%s)\t%#v\n", pos, filepath.Base(i.Name), s)
									}
								} else {
									if len(s) == len(args[1]) && s == args[1] {
										fmt.Printf("%#x: (%s)\t%#v\n", pos, filepath.Base(i.Name), s)
									}
								}
							}
						}
					}
				}
			}

			// objc cfstrings
			if cfstrs, err := m.GetCFStrings(); err == nil {
				if len(cfstrs) > 0 {
					for _, cfstr := range cfstrs {
						if len(pattern) > 0 {
							if strRE.MatchString(cfstr.Name) {
								fmt.Printf("%#09x: (%s)\t%#v\n", cfstr.Address, filepath.Base(i.Name), cfstr.Name)
							}
						} else {
							if contains && insensitive {
								if strings.Contains(strings.ToLower(cfstr.Name), strings.ToLower(args[1])) {
									fmt.Printf("%#09x: (%s)\t%#v\n", cfstr.Address, filepath.Base(i.Name), cfstr.Name)
								}
							} else if contains {
								if strings.Contains(cfstr.Name, args[1]) {
									fmt.Printf("%#09x: (%s)\t%#v\n", cfstr.Address, filepath.Base(i.Name), cfstr.Name)
								}
							} else if insensitive {
								if len(cfstr.Name) == len(args[1]) && strings.EqualFold(cfstr.Name, args[1]) {
									fmt.Printf("%#09x: (%s)\t%#v\n", cfstr.Address, filepath.Base(i.Name), cfstr.Name)
								}
							} else {
								if len(cfstr.Name) == len(args[1]) && cfstr.Name == args[1] {
									fmt.Printf("%#09x: (%s)\t%#v\n", cfstr.Address, filepath.Base(i.Name), cfstr.Name)
								}
							}
						}
					}
				}
			}
		}

		return nil
	},
}
