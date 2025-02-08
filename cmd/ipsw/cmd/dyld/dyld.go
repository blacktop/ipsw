/*
Copyright © 2018-2025 blacktop

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
	"path/filepath"

	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var symAddrColor = color.New(color.Faint).SprintfFunc()
var symImageColor = color.New(color.Faint, color.FgBlue).SprintfFunc()
var symTypeColor = color.New(color.Faint, color.FgCyan).SprintfFunc()
var symLibColor = color.New(color.Faint, color.FgMagenta).SprintfFunc()
var symNameColor = color.New(color.Bold).SprintFunc()

var colorAddr = color.New(color.Faint).SprintfFunc()
var colorImage = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
var colorField = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorClassField = color.New(color.Bold, color.FgHiMagenta).SprintFunc()

type dscFunc struct {
	Addr  uint64 `json:"addr,omitempty"`
	Start uint64 `json:"start,omitempty"`
	End   uint64 `json:"end,omitempty"`
	Size  uint64 `json:"size,omitempty"`
	Name  string `json:"name,omitempty"`
	Image string `json:"image,omitempty"`
}

func getDSCs(path string) []string {
	matches, err := filepath.Glob(filepath.Join(path, "dyld_shared_cache*"))
	if err != nil {
		return nil
	}
	return matches
}

func getImages(dscPath string) []string {
	var images []string
	if f, err := dyld.Open(dscPath); err == nil {
		defer f.Close()
		for _, image := range f.Images {
			images = append(images, filepath.Base(image.Name))
		}
	}
	return images
}

// DyldCmd represents the dyld command
var DyldCmd = &cobra.Command{
	Use:     "dyld",
	Aliases: []string{"dsc"},
	Short:   "Parse dyld_shared_cache",
	Args:    cobra.NoArgs,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		viper.BindPFlag("color", cmd.Flags().Lookup("color"))
		viper.BindPFlag("no-color", cmd.Flags().Lookup("no-color"))
		viper.BindPFlag("verbose", cmd.Flags().Lookup("verbose"))
		viper.BindPFlag("diff-tool", cmd.Flags().Lookup("diff-tool"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}
