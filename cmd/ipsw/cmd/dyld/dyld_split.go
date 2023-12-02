//go:build darwin && cgo

package dyld

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	semver "github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(SplitCmd)
	SplitCmd.Flags().StringP("xcode", "x", "", "Path to Xcode.app")
	SplitCmd.Flags().BoolP("cache", "c", false, "Build XCode device support cache")
	SplitCmd.Flags().StringP("version", "v", "", "Cache version")
	SplitCmd.Flags().StringP("build", "b", "", "Cache build")
	SplitCmd.Flags().StringP("output", "o", "", "Directory to extract the dylibs (default: CWD)")
	SplitCmd.MarkFlagDirname("output")
	viper.BindPFlag("dyld.split.xcode", SplitCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("dyld.split.cache", SplitCmd.Flags().Lookup("cache"))
	viper.BindPFlag("dyld.split.version", SplitCmd.Flags().Lookup("version"))
	viper.BindPFlag("dyld.split.build", SplitCmd.Flags().Lookup("build"))
	viper.BindPFlag("dyld.split.output", SplitCmd.Flags().Lookup("output"))
}

// SplitCmd represents the split command
var SplitCmd = &cobra.Command{
	Use:   "split <DSC>",
	Short: "Extracts all the dylibs using XCode's dsc_extractor",
	Args:  cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if viper.GetBool("verbose") {
			log.SetLevel(log.DebugLevel)
		}
		color.NoColor = viper.GetBool("no-color")

		// flags
		xcodePath := viper.GetString("dyld.split.xcode")
		version := viper.GetString("dyld.split.version")
		output := viper.GetString("dyld.split.output")
		// validate flags
		if runtime.GOOS != "darwin" {
			log.Fatal("dyld_shared_cache splitting only works on macOS (as it requires 'dsc_extractor.bundle')")
		} else if len(output) > 0 && viper.GetBool("dyld.split.cache") {
			return fmt.Errorf("cannot specify --output dir and use --cache flag at the same time")
		}
		if len(output) == 0 {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get current working directory: %w", err)
			}
			output = cwd
		} else {
			output, _ = filepath.Abs(filepath.Clean(output))
		}

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

		if viper.GetBool("dyld.split.cache") {
			if len(viper.GetString("dyld.split.build")) == 0 {
				return fmt.Errorf("--build is required when --cache is used")
			}

			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			f, err := dyld.Open(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to open %s", dscPath)
			}

			var arm64e string
			if strings.Contains(f.Headers[f.UUID].Magic.String(), "arm64e") {
				arm64e = " arm64e"
			}
			f.Close()

			if len(version) == 0 {
				version = f.Headers[f.UUID].OsVersion.String()
				if len(version) == 0 {
					return fmt.Errorf("--version is required when --cache is used")
				}
			}
			if _, err = semver.NewVersion(version); err != nil {
				return fmt.Errorf("invalid version: %s", version)
			}
			if strings.HasSuffix(version, ".0.0") {
				version = strings.TrimSuffix(version, ".0")
			}

			output = filepath.Join(home, fmt.Sprintf("/Library/Developer/Xcode/iOS DeviceSupport/%s (%s)%s", version, viper.GetString("dyld.split.build"), arm64e))
		}

		if err := os.MkdirAll(output, 0750); err != nil {
			return fmt.Errorf("failed to create output directory %s: %v", output, err)
		}

		log.Infof("Splitting to %s", output)
		return dyld.Split(dscPath, output, xcodePath, viper.GetBool("dyld.split.cache"))
	},
}
