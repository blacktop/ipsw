// +build darwin,cgo

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var deviceOsFlag string

func init() {
	dyldCmd.AddCommand(splitCmd)

	splitCmd.Flags().BoolP("iphone", "i", true, "Extract from iPhoneOS cache")
	splitCmd.Flags().BoolP("appletv", "a", false, "Extract from AppleTVOS cache")
	splitCmd.Flags().BoolP("watch", "w", false, "Extract from WatchOS cache")

	splitCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

func contains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func checkRequiredFlags(flags *pflag.FlagSet) error {
	requiredError := false
	flagSetCount := 0

	flags.VisitAll(func(flag *pflag.Flag) {
		if contains([]string{"iphone", "appletv", "watch"}, flag.Name) {
			if strings.EqualFold(flag.Value.String(), "true") {
				flagSetCount++
				switch flag.Name {
				case "iphone":
					deviceOsFlag = "iPhoneOS"
				case "appletv":
					deviceOsFlag = "AppleTVOS"
				case "watch":
					deviceOsFlag = "WatchOS"
				}
			}

			if flagSetCount > 1 {
				requiredError = true
			}
		}
	})

	if requiredError {
		return errors.New("Flags are mutually exclusive: please only set one of -i|-a|-w")
	}

	return nil
}

// splitCmd represents the split command
var splitCmd = &cobra.Command{
	Use:   "split <dyld_shared_cache> <optional_output_path>",
	Short: "Extracts all the dyld_shared_cache libraries",
	Args:  cobra.MinimumNArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return checkRequiredFlags(cmd.Flags())
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		var outputPath string

		dscPath := filepath.Clean(args[0])

		if len(args) > 1 {
			outputPath = filepath.Clean(args[1])
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				return fmt.Errorf("path %s does not exist", dscPath)
			}
		}

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

		if len(outputPath) > 0 {
			fullPath, _ := filepath.Abs(outputPath)
			log.Infof("Splitting dyld_shared_cache to %s\n", fullPath)
			return dyld.Split(dscPath, outputPath, deviceOsFlag)
		}
		log.Info("Splitting dyld_shared_cache")
		return dyld.Split(dscPath, filepath.Dir(dscPath), deviceOsFlag)
	},
}
