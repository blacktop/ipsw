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
package pipeline

import (
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/pipeline/static"
	"github.com/spf13/cobra"
)

func init() {
	PipelineCmd.AddCommand(initCmd)
}

// initCmd represents the list command
var initCmd = &cobra.Command{
	Use:           "init",
	Aliases:       []string{"i"},
	Short:         "Generates a .goreleaser.yaml file",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		conf, err := os.OpenFile(pipelineConf, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		defer conf.Close()

		log.Infof("Generating %s file", pipelineConf)
		if _, err := conf.WriteString(static.ExampleConfig); err != nil {
			return err
		}

		gitignore, err := os.OpenFile(".gitignore", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer gitignore.Close()
		if _, err := gitignore.WriteString("\ndist/\n"); err != nil {
			return err
		}

		log.WithField("file", pipelineConf).Info("config created; please edit accordingly to your needs")
		return nil
	},
}
