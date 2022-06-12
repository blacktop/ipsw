//go:build darwin && cgo

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

	splitCmd.Flags().StringP("xcode", "x", "", "Path to Xcode.app")
	viper.BindPFlag("dyld.split.xcode", splitCmd.Flags().Lookup("xcode"))

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
