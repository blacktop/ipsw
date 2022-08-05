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
package cmd

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var haveChecked []string

func scanDmg(ipswPath, dmgPath, dmgType, dylib string) error {
	if utils.StrSliceHas(haveChecked, dmgPath) {
		return nil // already checked
	}

	dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
		return strings.EqualFold(filepath.Base(f.Name), dmgPath)
	})
	if err != nil {
		return fmt.Errorf("failed to extract %s from IPSW: %v", dmgPath, err)
	}
	if len(dmgs) == 0 {
		return fmt.Errorf("failed to find %s in IPSW", dmgPath)
	}
	defer os.Remove(dmgs[0])

	utils.Indent(log.Info, 3)(fmt.Sprintf("Mounting %s %s", dmgType, dmgs[0]))
	mountPoint, err := utils.MountFS(dmgs[0])
	if err != nil {
		return fmt.Errorf("failed to mount DMG: %v", err)
	}
	defer func() {
		utils.Indent(log.Info, 3)(fmt.Sprintf("Unmounting %s", dmgs[0]))
		if err := utils.Unmount(mountPoint, false); err != nil {
			log.Errorf("failed to unmount DMG at %s: %v", dmgs[0], err)
		}
	}()

	var files []string
	if err := filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to walk files in dir %s: %v", mountPoint, err)
	}

	for _, file := range files {
		if m, err := macho.Open(file); err == nil {
			for _, imp := range m.ImportedLibraries() {
				if strings.Contains(strings.ToLower(imp), strings.ToLower(dylib)) {
					fmt.Printf("%s\n", file)
				}
			}
			m.Close()
		}
	}

	haveChecked = append(haveChecked, dmgPath)

	return nil
}

func init() {
	dyldCmd.AddCommand(importsCmd)
	importsCmd.Flags().BoolP("file-system", "f", false, "Scan File System in IPSW for MachO files that import dylib")
	importsCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// importsCmd represents the imports command
var importsCmd = &cobra.Command{
	Use:   "imports",
	Short: "List all dylibs that load a given dylib",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		scanFS, _ := cmd.Flags().GetBool("file-system")

		if scanFS {
			ipswPath := filepath.Clean(args[0])

			i, err := info.Parse(ipswPath)
			if err != nil {
				return fmt.Errorf("failed to parse IPSW: %v", err)
			}

			if appOS, err := i.GetAppOsDmg(); err == nil {
				if err := scanDmg(ipswPath, appOS, "AppOS", args[1]); err != nil {
					return fmt.Errorf("failed to scan files in AppOS %s: %v", appOS, err)
				}
			}
			if systemOS, err := i.GetSystemOsDmg(); err == nil {
				if err := scanDmg(ipswPath, systemOS, "SystemOS", args[1]); err != nil {
					return fmt.Errorf("failed to scan files in SystemOS %s: %v", systemOS, err)
				}
			}
			if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
				if err := scanDmg(ipswPath, fsOS, "filesystem", args[1]); err != nil {
					return fmt.Errorf("failed to scan files in filesystem %s: %v", fsOS, err)
				}
			}
		} else {
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

			image, err := f.Image(args[1])
			if err != nil {
				return fmt.Errorf("image not in %s: %v", dscPath, err)
			}

			title := fmt.Sprintf("\n%s Imported By:\n", filepath.Base(image.Name))
			fmt.Print(title)
			fmt.Println(strings.Repeat("=", len(title)-1))
			for _, img := range f.Images {
				m, err := img.GetPartialMacho()
				if err != nil {
					return err
				}
				for _, imp := range m.ImportedLibraries() {
					if strings.EqualFold(imp, image.Name) {
						fmt.Printf("%s\n", img.Name)
					}
				}
				m.Close()
			}
		}

		return nil
	},
}
