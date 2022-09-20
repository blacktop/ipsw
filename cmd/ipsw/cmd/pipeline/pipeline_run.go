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
	"github.com/blacktop/ipsw/internal/pipeline"
	"github.com/blacktop/ipsw/internal/pipeline/config"
	"github.com/blacktop/ipsw/internal/pipeline/context"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/errhandler"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/logging"
	"github.com/blacktop/ipsw/internal/pipeline/middleware/skip"
	"github.com/caarlos0/ctrlc"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	PipelineCmd.AddCommand(runCmd)

	runCmd.Flags().DurationP("timeout", "t", 0, "Timeout for pipeline")
	viper.BindPFlag("pipeline.run.timeout", runCmd.Flags().Lookup("timeout"))
}

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:           "run <pipeline>",
	Short:         "Run ipsw pipeline",
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(pipelineConf)
		if err != nil {
			return err
		}
		ctx, cancel := context.NewWithTimeout(cfg, viper.GetDuration("pipeline.run.timeout"))
		defer cancel()
		// setupReleaseContext(ctx, options)
		return ctrlc.Default.Run(ctx, func() error {
			for _, pipe := range pipeline.Pipeline {
				if err := skip.Maybe(
					pipe,
					logging.Log(
						pipe.String(),
						errhandler.Handle(pipe.Run),
					),
				)(ctx); err != nil {
					return err
				}
			}
			return nil
		})
	},
}
