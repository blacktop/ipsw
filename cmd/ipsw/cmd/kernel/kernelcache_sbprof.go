/*
Copyright © 2018-2022 blacktop

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
package kernel

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	KernelcacheCmd.AddCommand(sbprofCmd)

	sbprofCmd.MarkZshCompPositionalArgumentFile(1, "kernelcache*")
}

// sbprofCmd represents the sbprof command
var sbprofCmd = &cobra.Command{
	Use:    "sbprof",
	Short:  "🚧 [WIP] Extract kernel sandbox profile data",
	Args:   cobra.MinimumNArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		kcPath := filepath.Clean(args[0])

		if _, err := os.Stat(kcPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", args[0])
		}

		m, err := macho.Open(kcPath)
		if err != nil {
			return err
		}
		defer m.Close()

		data, err := os.ReadFile(kcPath)
		if err != nil {
			return err
		}

		the_real_platform_profile_data, err := kernelcache.GetSandboxProfiles(m, bytes.NewReader(data))
		if err != nil {
			return err
		}

		sbProfPath := filepath.Join(filepath.Dir(kcPath), "sandbox_profile.bin")
		err = os.WriteFile(sbProfPath, the_real_platform_profile_data, 0660)
		if err != nil {
			return err
		}
		log.Info("Created " + sbProfPath)

		collection_data, err := kernelcache.GetSandboxCollections(m, bytes.NewReader(data))
		if err != nil {
			return err
		}

		sbColPath := filepath.Join(filepath.Dir(kcPath), "sandbox_collection.bin")
		err = os.WriteFile(sbColPath, collection_data, 0660)
		if err != nil {
			return err
		}
		log.Info("Created " + sbColPath)

		log.Info("Parsing " + sbColPath)
		sbOpsList, err := kernelcache.GetSandboxOpts(m)
		if err != nil {
			return err
		}
		_, err = kernelcache.ParseSandboxCollection(collection_data, sbOpsList)
		if err != nil {
			return err
		}

		// regexFolder := filepath.Join(filepath.Dir(kcPath), "regex")
		// os.MkdirAll(regexFolder, 0750)

		// for off, data := range sb.Regexes {
		// 	regexPath := filepath.Join(regexFolder, fmt.Sprintf("regex_%x", off))
		// 	err = os.WriteFile(regexPath, data, 0660)
		// 	if err != nil {
		// 		return err
		// 	}
		// }

		return nil
	},
}
