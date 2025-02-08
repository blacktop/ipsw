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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/config"
	"github.com/invopop/jsonschema"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(jsonschemaCmd)
	jsonschemaCmd.Flags().StringP("output", "o", "", "Where to save the JSONSchema file")
	viper.BindPFlag("jsonschema.output", jsonschemaCmd.Flags().Lookup("output"))
}

// jsonschemaCmd represents the jsonschema command
var jsonschemaCmd = &cobra.Command{
	Use:           "jsonschema",
	Aliases:       []string{"schema"},
	Short:         "Output ipsw's JSON schema",
	Args:          cobra.NoArgs,
	SilenceUsage:  true,
	SilenceErrors: true,
	Hidden:        true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		schema := jsonschema.Reflect(&config.Config{})
		schema.Description = "ipsw configuration definition file"
		bts, err := json.MarshalIndent(schema, "	", "	")
		if err != nil {
			return fmt.Errorf("failed to create jsonschema: %w", err)
		}
		if viper.GetString("jsonschema.output") == "-" {
			fmt.Println(string(bts))
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(viper.GetString("jsonschema.output")), 0o755); err != nil {
			return fmt.Errorf("failed to write jsonschema file: %w", err)
		}
		if err := os.WriteFile(viper.GetString("jsonschema.output"), bts, 0o666); err != nil {
			return fmt.Errorf("failed to write jsonschema file: %w", err)
		}

		return nil
	},
}
