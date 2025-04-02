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
	"fmt"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(uniqCmd)
}

// uniqCmd represents the uniq command
var uniqCmd = &cobra.Command{
	Use:     "uniq",
	Aliases: []string{"u"},
	Short:   "Get unique imports from an image in a dyld_shared_cache",
	Args:    cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	SilenceUsage:  true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		dsc, err := dyld.Open(args[0])
		if err != nil {
			return err
		}
		defer dsc.Close()

		targetImage, err := dsc.Image(args[1])
		if err != nil {
			return fmt.Errorf("failed to find target image %s: %w", args[1], err)
		}

		// Keep track of target image imports
		var targetImports []string
		// Keep track of all imports from *other* images
		otherImports := make(map[string]struct{})

		for _, image := range dsc.Images {
			m, err := image.GetPartialMacho()
			if err != nil {
				log.WithError(err).Warnf("failed to get macho for image %s, skipping", image.Name)
				continue // Skip this image if there's an error
			}
			defer m.Close() // Ensure closure within the loop

			currentImports := m.ImportedLibraries()

			if image.Name == targetImage.Name {
				targetImports = currentImports
			} else {
				for _, lib := range currentImports {
					otherImports[lib] = struct{}{} // Add to the set of other imports
				}
			}
		}

		var uniq []string
		if targetImports == nil {
			// This case might indicate the target image loop entry didn't run, which shouldn't happen if dsc.Image() succeeded
			// but checking defensively.
			log.Warnf("Target image %s found but its imports were not processed", filepath.Base(targetImage.Name))
		} else {
			for _, lib := range targetImports {
				if _, found := otherImports[lib]; !found {
					uniq = append(uniq, lib)
				}
			}
		}

		if len(uniq) == 0 {
			log.Warnf("No unique imports found for %s", filepath.Base(targetImage.Name))
			return nil
		}

		log.WithField("count", len(uniq)).Infof("Found unique imports for %s", filepath.Base(targetImage.Name))
		for _, u := range uniq {
			utils.Indent(log.Info, 2)(u)
		}

		return nil
	},
}
