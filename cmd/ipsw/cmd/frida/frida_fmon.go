//go:build darwin && frida

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
package frida

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/apex/log"
	"github.com/caarlos0/ctrlc"
	"github.com/fatih/color"
	"github.com/frida/frida-go/frida"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	FridaCmd.AddCommand(fridaFMonCmd)
}

// fridaFMonCmd represents the fmon command
var fridaFMonCmd = &cobra.Command{
	Use:           "fmon",
	Aliases:       []string{"fm"},
	Short:         "File Monitor",
	SilenceUsage:  true,
	SilenceErrors: true,
	Args:          cobra.ExactArgs(1),
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// udid := viper.GetString("frida.udid")

		mon := frida.NewFileMonitor(args[0])
		if err := mon.Enable(); err != nil {
			panic(err)
		}

		mon.On("change", func(changedFile, otherFile, changeType string) {
			fmt.Printf("[*] File %s has changed (%s)\n", changedFile, changeType)
		})

		log.Infof("Monitoring path: %s", mon.Path())

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := ctrlc.Default.Run(ctx, func() error {
			s := bufio.NewScanner(os.Stdin)
			for s.Scan() {
				fmt.Println(s.Text())
			}
			return nil
		}); err != nil {
			log.Warn("Disabling Monitor...")
			if err := mon.Disable(); err != nil {
				return fmt.Errorf("failed to disable monitor: %v", err)
			}
		}

		return nil
	},
}
