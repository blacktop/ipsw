/*
Copyright © 2018-2024 blacktop

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
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	dscCmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(StrSearchCmd)
	StrSearchCmd.Flags().StringP("pattern", "p", "", "Regex match strings (SLOW)")
	viper.BindPFlag("dyld.str.pattern", StrSearchCmd.Flags().Lookup("pattern"))
}

// StrSearchCmd represents the str command
var StrSearchCmd = &cobra.Command{
	Use:   "str <DSC> [STRING...]",
	Short: "Search dyld_shared_cache for string",
	Example: `  # Perform FAST byte search for string in dyld_shared_cache
  ❯ ipsw dsc str DSC "string1"
  # Perform FAST byte search for multiple strings in dyld_shared_cache
  ❯ ipsw dsc str DSC "string1" "string2"
  # Perform FAST byte search for strings from stdin in dyld_shared_cache
  ❯ cat strings.txt | ipsw dsc str DSC
  # Perform SLOW regex search for string in dyld_shared_cache
  ❯ ipsw dsc str DSC --pattern "REGEX_PATTERN"`,
	Args: cobra.MinimumNArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		pattern := viper.GetString("dyld.str.pattern")
		// validate flags
		if pattern != "" && len(args) > 1 {
			return fmt.Errorf("cannot use --pattern with positional STRING arguments")
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

		var strs []dscCmd.String

		if pattern != "" {
			log.Info("Searching for strings via REGEX pattern...")
			strs, err = dscCmd.GetStringsRegex(f, pattern)
			if err != nil {
				return err
			}
		} else {
			var searchStrings []string

			if len(args) > 1 {
				// Read from positional args
				searchStrings = args[1:]
			} else {
				// Read from stdin
				stat, err := os.Stdin.Stat()
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %v", err)
				}
				if (stat.Mode() & os.ModeCharDevice) == 0 {
					reader := bufio.NewReader(os.Stdin)
					var inputBuilder strings.Builder
					for {
						part, err := reader.ReadString('\n')
						if err == io.EOF {
							if len(part) > 0 {
								inputBuilder.WriteString(part)
							}
							break
						}
						if err != nil {
							return fmt.Errorf("failed to read from stdin: %v", err)
						}
						inputBuilder.WriteString(part)
					}
					searchStrings = strings.Split(inputBuilder.String(), "\n")
				} else {
					return fmt.Errorf("no input provided via stdin")
				}
			}
			log.Infof("Searching for strings: %s", strings.Join(searchStrings, ", "))
			strs, err = dscCmd.GetStrings(f, searchStrings...)
			if err != nil {
				return err
			}
		}

		var out strings.Builder
		for _, str := range strs {
			out.Reset()
			out.WriteString(fmt.Sprintf("%s: \"%s\"", colorAddr("%#x", str.Address), str.String))
			if str.Address == 0 {
				out.WriteString(fmt.Sprintf("\t%s=%s", colorField("offset"), colorAddr("%#x", str.Offset)))
			}
			if str.Image != "" {
				out.WriteString(fmt.Sprintf("\t%s=%s", colorField("image"), colorImage(str.Image)))
			} else {
				if str.Mapping != "" {
					out.WriteString(fmt.Sprintf("\t%s=%s", colorField("mapping"), symLibColor(str.Mapping)))
				}
			}
			fmt.Println(out.String())
		}

		return nil
	},
}
