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
package disk

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DiskCmd.AddCommand(dmgCmd)

	dmgCmd.Flags().StringP("re", "r", "", "Extract partition that matches regex")
	dmgCmd.Flags().IntP("partition", "p", -1, "Extract a specific partition by number")
	dmgCmd.Flags().StringP("password", "w", "", "Encrypted DMG password")
	viper.BindPFlag("dmg.re", dmgCmd.Flags().Lookup("re"))
	viper.BindPFlag("dmg.partition", dmgCmd.Flags().Lookup("partition"))
	viper.BindPFlag("dmg.password", dmgCmd.Flags().Lookup("password"))
}

// dmgCmd represents the dmg command
var dmgCmd = &cobra.Command{
	Use:           "dmg DMG [OUTPUT]",
	Short:         "🚧 List/Extract DMG partiton/blocks",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) (err error) {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		pattern := viper.GetString("dmg.re")
		partition := viper.GetInt("dmg.partition")
		password := viper.GetString("dmg.password")
		// validate args
		if viper.IsSet("dmg.partition") && viper.IsSet("dmg.re") {
			return fmt.Errorf("cannot specify both --partition and --re")
		}
		if len(args) > 1 && !viper.IsSet("dmg.partition") && !viper.IsSet("dmg.re") {
			return fmt.Errorf("no partition specified. (use --partition or --re)")
		}
		if len(args) == 1 && (viper.IsSet("dmg.partition") || viper.IsSet("dmg.re")) {
			return fmt.Errorf("no output file specified")
		}

		infile := filepath.Clean(args[0])

		if isDMG, err := magic.IsDMG(infile); err != nil {
			return fmt.Errorf("failed to read DMG magic: %w", err)
		} else if !isDMG {
			return fmt.Errorf("file is not a DMG file")
		}

		d, err := dmg.Open(infile, &dmg.Config{Password: password})
		if err != nil {
			if errors.Is(err, dmg.ErrEncrypted) {
				return fmt.Errorf("DMG is encrypted. Use --password to specify password")
			}
			return fmt.Errorf("failed to open DMG: %w", err)
		}
		defer d.Close()

		if len(d.Partitions) == 0 {
			return fmt.Errorf("no partitions found in DMG")
		}

		var p *dmg.Partition

		if len(args) == 1 {
			for idx, p := range d.Partitions {
				log.Infof("%d) %s", idx, p.Name)
			}
			return nil
		} else {
			if viper.IsSet("dmg.partition") {
				if partition > len(d.Partitions)-1 || partition < 0 {
					return fmt.Errorf("partition number out of range (there are %d partitions)", len(d.Partitions))
				}
				p = &d.Partitions[partition]
			} else if viper.IsSet("dmg.re") {
				re, err := regexp.Compile(pattern)
				if err != nil {
					return fmt.Errorf("failed to compile regex '%s': %w", pattern, err)
				}
				for _, part := range d.Partitions {
					if re.MatchString(part.Name) {
						p = &part
						break
					}
				}
			} else {
				return fmt.Errorf("no partition specified. (use --partition or --re)")
			}
		}

		if p == nil {
			return fmt.Errorf("no partition found matching criteria")
		}

		o, err := os.Create(args[1])
		if err != nil {
			return err
		}
		defer o.Close()

		w := bufio.NewWriter(o)
		if err := p.Write(w); err != nil {
			return fmt.Errorf("failed to write disk image: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("failed to flush buffer: %w", err)
		}

		log.Infof("Extracted '%s' as %s", p.Name, args[1])

		return nil
	},
}
