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
package macho

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(lipoCmd)

	lipoCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	lipoCmd.Flags().String("output", "", "Directory to extract the MachO")
	viper.BindPFlag("macho.lipo.arch", lipoCmd.Flags().Lookup("arch"))
	viper.BindPFlag("macho.lipo.output", lipoCmd.Flags().Lookup("output"))
	lipoCmd.MarkZshCompPositionalArgumentFile(1)
}

// lipoCmd represents the lipo command
var lipoCmd = &cobra.Command{
	Use:     "lipo",
	Aliases: []string{"l"},
	Short:   "Extract single MachO out of a universal/fat MachO",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		var farch macho.FatArch

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		selectedArch := viper.GetString("macho.lipo.arch")
		extractPath := viper.GetString("macho.lipo.output")

		machoPath := filepath.Clean(args[0])

		if _, err := os.Stat(machoPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", machoPath)
		}

		// first check for fat file
		fat, err := macho.OpenFat(machoPath)
		if err != nil {
			if err == macho.ErrNotFat {
				return fmt.Errorf("input file is not a universal/fat MachO")
			}
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer fat.Close()

		var options []string
		var shortOptions []string
		for _, arch := range fat.Arches {
			options = append(options, fmt.Sprintf("%s, %s", arch.CPU, arch.SubCPU.String(arch.CPU)))
			shortOptions = append(shortOptions, strings.ToLower(arch.SubCPU.String(arch.CPU)))
		}

		if len(selectedArch) > 0 {
			found := false
			for i, opt := range shortOptions {
				if strings.Contains(strings.ToLower(opt), strings.ToLower(selectedArch)) {
					farch = fat.Arches[i]
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("--arch '%s' not found in: %s", selectedArch, strings.Join(shortOptions, ", "))
			}
		} else {
			choice := 0
			prompt := &survey.Select{
				Message: "Detected a universal MachO file, please select an architecture to extract:",
				Options: options,
			}
			survey.AskOne(prompt, &choice)
			farch = fat.Arches[choice]
		}

		f, err := os.Open(machoPath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %v", machoPath, err)
		}
		defer f.Close()

		dat := make([]byte, farch.Size)
		if _, err := f.ReadAt(dat, int64(farch.Offset)); err != nil {
			return fmt.Errorf("failed to read data in file at %#x: %v", farch.Offset, err)
		}

		outFile := fmt.Sprintf("%s.%s", machoPath, strings.ToLower(farch.SubCPU.String(farch.CPU)))
		folder := filepath.Dir(outFile) // default to folder of shared cache
		if len(extractPath) > 0 {
			folder = extractPath
		}
		fname := filepath.Join(folder, filepath.Base(outFile)) // default to NOT full dylib path
		if err := os.WriteFile(fname, dat, 0660); err != nil {
			return fmt.Errorf("failed to create file %s: %v", outFile, err)
		}
		log.Infof("Extracted %s file as %s", farch.SubCPU.String(farch.CPU), fname)

		return nil
	},
}
