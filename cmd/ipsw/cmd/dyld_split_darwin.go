//go:build darwin && cgo

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	dyldCmd.AddCommand(splitCmd)

	splitCmd.Flags().StringP("xcode", "x", "", "Path to Xcode.app")
	splitCmd.Flags().BoolP("cache", "c", false, "Build XCode device support cache")
	splitCmd.Flags().StringP("version", "v", "", "Cache version")
	splitCmd.Flags().StringP("build", "b", "", "Cache build")
	viper.BindPFlag("dyld.split.xcode", splitCmd.Flags().Lookup("xcode"))
	viper.BindPFlag("dyld.split.cache", splitCmd.Flags().Lookup("cache"))
	viper.BindPFlag("dyld.split.version", splitCmd.Flags().Lookup("version"))
	viper.BindPFlag("dyld.split.build", splitCmd.Flags().Lookup("build"))

	splitCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// splitCmd represents the split command
var splitCmd = &cobra.Command{
	Use:           "split <dyld_shared_cache> <optional_output_path>",
	Short:         "Extracts all the dyld_shared_cache libraries",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  false,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		xcodePath := viper.GetString("dyld.split.xcode")
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

		outputPath := filepath.Dir(dscPath)

		if len(args) > 1 && viper.GetBool("dyld.split.cache") {
			return fmt.Errorf("cannot specify output path and use --cache flag at the same time")
		} else if len(args) > 1 {
			outputPath, _ := filepath.Abs(filepath.Clean(args[1]))
			if _, err := os.Stat(outputPath); os.IsNotExist(err) {
				return fmt.Errorf("path %s does not exist", outputPath)
			}
		} else if viper.GetBool("dyld.split.cache") {
			if len(viper.GetString("dyld.split.version")) == 0 || len(viper.GetString("dyld.split.build")) == 0 {
				return fmt.Errorf("--version and --build are required when --cache is used")
			}

			home, err := homedir.Dir()
			if err != nil {
				return err
			}

			f, err := dyld.Open(dscPath)
			if err != nil {
				return errors.Wrapf(err, "failed to open dyld_shared_cache %s", dscPath)
			}

			var arm64e string
			if strings.Contains(f.Headers[f.UUID].Magic.String(), "arm64e") {
				arm64e = " arm64e"
			}
			f.Close()

			version := viper.GetString("dyld.split.version")
			if strings.HasSuffix(version, ".0.0") {
				version = strings.TrimSuffix(version, ".0")
			}

			outputPath = filepath.Join(home, fmt.Sprintf("/Library/Developer/Xcode/iOS DeviceSupport/%s (%s)%s", version, viper.GetString("dyld.split.build"), arm64e))
			if err := os.MkdirAll(outputPath, 0755); err != nil {
				return fmt.Errorf("failed to create cache directory %s: %v", outputPath, err)
			}
		}

		log.Infof("Splitting dyld_shared_cache to %s\n", outputPath)
		return dyld.Split(dscPath, outputPath, xcodePath, viper.GetBool("dyld.split.cache"))

		// dscPath := filepath.Clean(args[0])

		// fileInfo, err := os.Lstat(dscPath)
		// if err != nil {
		// 	return fmt.Errorf("file %s does not exist", dscPath)
		// }

		// // Check if file is a symlink
		// if fileInfo.Mode()&os.ModeSymlink != 0 {
		// 	symlinkPath, err := os.Readlink(dscPath)
		// 	if err != nil {
		// 		return errors.Wrapf(err, "failed to read symlink %s", dscPath)
		// 	}
		// 	// TODO: this seems like it would break
		// 	linkParent := filepath.Dir(dscPath)
		// 	linkRoot := filepath.Dir(linkParent)

		// 	dscPath = filepath.Join(linkRoot, symlinkPath)
		// }

		// f, err := dyld.Open(dscPath)
		// if err != nil {
		// 	return err
		// }
		// defer f.Close()

		// var wg sync.WaitGroup

		// for _, i := range f.Images {
		// 	wg.Add(1)

		// 	go func(i *dyld.CacheImage) {
		// 		defer wg.Done()

		// 		m, err := i.GetMacho()
		// 		if err != nil {
		// 			// return err
		// 		}
		// 		defer m.Close()

		// 		// f.GetLocalSymbolsForImage(i)

		// 		folder := filepath.Dir(dscPath)        // default to folder of shared cache
		// 		fname := filepath.Join(folder, i.Name) // default to full dylib path

		// 		if err := m.Export(fname, nil, m.GetBaseAddress(), i.GetLocalSymbols()); err != nil {
		// 			// return fmt.Errorf("failed to export entry MachO %s; %v", i.Name, err)
		// 		}

		// 		if err := rebaseMachO(f, fname); err != nil {
		// 			// return fmt.Errorf("failed to rebase macho via cache slide info: %v", err)
		// 		}
		// 	}(i)

		// }

		// wg.Wait()

		// return nil
	},
}
