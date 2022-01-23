//go:build !darwin

package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/vbauerster/mpb/v7"
	"github.com/vbauerster/mpb/v7/decor"
)

func init() {
	dyldCmd.AddCommand(splitCmd)
	splitCmd.Flags().BoolP("all", "a", false, "Split ALL dylibs")
	splitCmd.Flags().Bool("force", false, "Overwrite existing extracted dylib(s)")
	splitCmd.Flags().String("output", "o", "Directory to extract the dylib(s)")
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

		var bar *mpb.Bar

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		dumpALL, _ := cmd.Flags().GetBool("all")
		forceExtract, _ := cmd.Flags().GetBool("force")
		extractPath, _ := cmd.Flags().GetString("output")

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

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		if len(args) > 1 || dumpALL {

			var images []*dyld.CacheImage

			if dumpALL {
				images = f.Images
				// initialize progress bar
				p := mpb.New(mpb.WithWidth(80))
				// adding a single bar, which will inherit container's width
				bar = p.Add(int64(len(images)),
					// progress bar filler with customized style
					mpb.NewBarFiller(mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|")),
					mpb.PrependDecorators(
						decor.Name("     ", decor.WC{W: len("     ") + 1, C: decor.DidentRight}),
						// replace ETA decorator with "done" message, OnComplete event
						decor.OnComplete(
							decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 4}), "✅ ",
						),
					),
					mpb.AppendDecorators(
						decor.Percentage(),
						// decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_GO, float64(len(images))/2048), "✅ "),
						decor.Name(" ] "),
					),
				)
			} else {
				image, err := f.Image(args[1])
				if err != nil {
					return fmt.Errorf("image not in %s: %v", dscPath, err)
				}
				images = append(images, image)
			}

			for _, i := range images {
				m, err := i.GetMacho()
				if err != nil {
					return err
				}

				folder := filepath.Dir(dscPath) // default to folder of shared cache
				if len(extractPath) > 0 {
					folder = extractPath
				}

				fname := filepath.Join(folder, filepath.Base(i.Name)) // default to NOT full dylib path
				if dumpALL {
					fname = filepath.Join(folder, i.Name)
				}

				if _, err := os.Stat(fname); os.IsNotExist(err) || forceExtract {

					i.ParseLocalSymbols(false)

					if err := m.Export(fname, nil, m.GetBaseAddress(), i.GetLocalSymbols()); err != nil {
						return fmt.Errorf("failed to export entry MachO %s; %v", i.Name, err)
					}

					if err := rebaseMachO(f, fname); err != nil {
						return fmt.Errorf("failed to rebase macho via cache slide info: %v", err)
					}

					if !dumpALL {
						log.Infof("Created %s", fname)
					} else {
						bar.Increment()
					}
				} else {
					if !dumpALL {
						log.Warnf("dylib already exists: %s", fname)
					} else {
						bar.Increment()
					}
				}
				m.Close()
			}
		}

		return nil
	},
}
