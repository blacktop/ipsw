//go:build darwin && cgo
// +build darwin,cgo

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	dyldCmd.AddCommand(splitCmd)

	splitCmd.Flags().StringP("xcode", "x", viper.GetString("IPSW_XCODE_PATH"), "Path to Xcode.app")

	splitCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// splitCmd represents the split command
var splitCmd = &cobra.Command{
	Use:   "split <dyld_shared_cache> <optional_output_path>",
	Short: "Extracts all the dyld_shared_cache libraries",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		xcodePath, _ := cmd.Flags().GetString("xcode")

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to read symlink %s", dscPath)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		if runtime.GOOS != "darwin" {
			log.Fatal("dyld_shared_cache splitting only works on macOS")
		}

		if len(args) > 1 {
			outputPath, _ := filepath.Abs(filepath.Clean(args[1]))
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				return fmt.Errorf("path %s does not exist", outputPath)
			}
			log.Infof("Splitting dyld_shared_cache to %s\n", outputPath)
			return dyld.Split(dscPath, outputPath, xcodePath)
		}

		log.Info("Splitting dyld_shared_cache")
		return dyld.Split(dscPath, filepath.Dir(dscPath), xcodePath)
	},
}
