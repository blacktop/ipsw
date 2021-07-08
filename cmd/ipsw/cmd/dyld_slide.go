/*
Copyright © 2021 blacktop

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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(slideCmd)
	slideCmd.Flags().BoolP("auth", "a", false, "Print only slide info for mappings with auth flags")
	slideCmd.Flags().StringP("cache", "c", "", "path to addr to sym cache file")
	slideCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// slideCmd represents the slide command
var slideCmd = &cobra.Command{
	Use:   "slide [options] <dyld_shared_cache>",
	Short: "Get slide info chained pointers",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		printAuthSlideInfo, _ := cmd.Flags().GetBool("auth")
		cacheFile, _ := cmd.Flags().GetString("cache")

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

		if len(cacheFile) == 0 {
			cacheFile = dscPath + ".a2s"
		}

		if err := f.OpenOrCreateA2SCache(cacheFile); err != nil {
			return err
		}

		if f.SlideInfoOffsetUnused > 0 {
			f.ParseSlideInfo(dyld.CacheMappingAndSlideInfo{
				Address:         f.Mappings[1].Address,
				Size:            f.Mappings[1].Size,
				FileOffset:      f.Mappings[1].FileOffset,
				SlideInfoOffset: f.SlideInfoOffsetUnused,
				SlideInfoSize:   f.SlideInfoSizeUnused,
			}, false)
		} else {
			for _, extMapping := range f.MappingsWithSlideInfo {
				if printAuthSlideInfo && !extMapping.Flags.IsAuthData() {
					continue
				}
				if extMapping.SlideInfoSize > 0 {
					f.ParseSlideInfo(extMapping.CacheMappingAndSlideInfo, true)
				}
			}
		}

		return nil
	},
}
