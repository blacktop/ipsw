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
package img4

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/dustin/go-humanize"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	Img4Cmd.AddCommand(img4PersonalizeCmd)

	// Personalize command flags
	img4PersonalizeCmd.Flags().StringP("component", "c", "", "Component name for fourcc patching")
	img4PersonalizeCmd.Flags().StringP("output", "o", "", "Output personalized IMG4 file")
	img4PersonalizeCmd.Flags().StringP("manifest", "m", "", "IM4M manifest file (from TSS response)")
	img4PersonalizeCmd.MarkFlagRequired("output")
	img4PersonalizeCmd.MarkFlagRequired("manifest")
	img4PersonalizeCmd.MarkFlagFilename("output")
	img4PersonalizeCmd.MarkFlagFilename("manifest")
	img4PersonalizeCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("img4.person.component", img4PersonalizeCmd.Flags().Lookup("component"))
	viper.BindPFlag("img4.person.output", img4PersonalizeCmd.Flags().Lookup("output"))
	viper.BindPFlag("img4.person.manifest", img4PersonalizeCmd.Flags().Lookup("manifest"))
}

// img4PersonalizeCmd represents the personalize command
var img4PersonalizeCmd = &cobra.Command{
	Use:     "person <IM4P>",
	Aliases: []string{"p", "personalize"},
	Short:   "🚧 Create personalized IMG4 with TSS manifest",
	Example: heredoc.Doc(`
		# Personalize IM4P with TSS manifest
		❯ ipsw img4 person --manifest tss_manifest.im4m --output personalized.img4 kernel.im4p

		# Personalize with specific component name for FourCC patching
		❯ ipsw img4 person --component KernelCache --manifest tss.im4m --output kernel.img4 kernel.im4p`),
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// flags
		outputPath := viper.GetString("img4.person.output")
		manifestPath := viper.GetString("img4.person.manifest")
		component := viper.GetString("img4.person.component")

		im4pPath := filepath.Clean(args[0])

		// Read the input IM4P
		im4pData, err := os.ReadFile(im4pPath)
		if err != nil {
			return fmt.Errorf("failed to read input IM4P: %v", err)
		}

		// Read the TSS manifest
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest file: %v", err)
		}

		// Create personalized IMG4
		personalizedImg, err := img4.Personalize(&img4.PersonalizeConfig{
			PayloadData:  im4pData,
			ManifestData: manifestData,
			Component:    component,
		})
		if err != nil {
			return fmt.Errorf("failed to create personalized IMG4: %v", err)
		}

		personalizedData, err := personalizedImg.Marshal()
		if err != nil {
			return fmt.Errorf("failed to marshal personalized IMG4: %v", err)
		}

		if err := os.WriteFile(outputPath, personalizedData, 0644); err != nil {
			return fmt.Errorf("failed to write personalized IMG4: %v", err)
		}

		log.WithFields(log.Fields{
			"path": outputPath,
			"size": humanize.Bytes(uint64(len(personalizedData))),
		}).Info("Personalized IMG4 created successfully")

		return nil
	},
}
