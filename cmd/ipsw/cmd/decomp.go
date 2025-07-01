//go:build darwin && cgo

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
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/comp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(decompCmd)
	decompCmd.Flags().StringP("output", "o", "", "Output file path")
	// Mark required flags
	decompCmd.MarkFlagRequired("output")
	// Mark file flags
	decompCmd.MarkFlagFilename("output")
	decompCmd.Flags().StringP("algo", "a", "", "Use a specific algorithm for decompression")
	// Flag tab completion
	decompCmd.RegisterFlagCompletionFunc("algo", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return comp.Algorithms(), cobra.ShellCompDirectiveDefault
	})
	viper.BindPFlag("decomp.algo", decompCmd.Flags().Lookup("algo"))
	viper.BindPFlag("decomp.output", decompCmd.Flags().Lookup("output"))
}

// decompCmd represents the decomp command
var decompCmd = &cobra.Command{
	Use:           "decomp",
	Short:         "Decompress files using libcompression",
	Args:          cobra.ExactArgs(1),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		algo := viper.GetString("decomp.algo")
		compAlgo, err := comp.Lookup(algo)
		if err != nil {
			return err
		}

		infile := filepath.Clean(args[0])
		outFile := viper.GetString("decomp.output")

		data, err := os.ReadFile(infile)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %v", infile, err)
		}

		decompressedData, err := comp.Decompress(data, compAlgo)
		if err != nil {
			return fmt.Errorf("failed to decompress file: %v", err)
		}

		if outFile == "-" {
			// Write to stdout
			if _, err := os.Stdout.Write(decompressedData); err != nil {
				return fmt.Errorf("failed to write to stdout: %v", err)
			}
		} else {
			// Write to specified output file
			if err := os.WriteFile(outFile, decompressedData, 0644); err != nil {
				return fmt.Errorf("failed to write decompressed data to %s: %v", outFile, err)
			}
			log.WithFields(log.Fields{
				"output": outFile,
				"size":   len(decompressedData),
			}).Info("Decompressed File")
		}

		return nil
	},
}
