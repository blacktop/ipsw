/*
Copyright © 2021 blacktop

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
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func init() {
	dyldCmd.AddCommand(a2sCmd)

	a2sCmd.Flags().Uint64P("slide", "s", 0, "dyld_shared_cache slide to apply")
	a2sCmd.Flags().BoolP("image", "i", false, "Only lookup address's dyld_shared_cache mapping")
	a2sCmd.Flags().BoolP("mapping", "m", false, "Only lookup address's image segment/section")

	a2sCmd.MarkZshCompPositionalArgumentFile(1, "dyld_shared_cache*")
}

// a2sCmd represents the a2s command
var a2sCmd = &cobra.Command{
	Use:   "a2s <dyld_shared_cache> <vaddr>",
	Short: "Lookup symbol at unslid address",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		slide, _ := cmd.Flags().GetUint64("slide")
		showImage, _ := cmd.Flags().GetBool("image")
		showMapping, _ := cmd.Flags().GetBool("mapping")

		secondAttempt := false

		addr, err := utils.ConvertStrToInt(args[1])
		if err != nil {
			return err
		}

		var unslidAddr uint64 = addr
		if slide > 0 {
			unslidAddr = addr - slide
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

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		// Load all symbols
		// if _, err := os.Stat(dscPath + ".a2s"); os.IsNotExist(err) {
		// 	log.Info("Generating dyld_shared_cache companion symbol map file...")

		// 	// utils.Indent(log.Warn, 2)("parsing public symbols...")
		// 	// err = f.GetAllExportedSymbols(false)
		// 	// if err != nil {
		// 	// 	return err
		// 	// }
		// 	utils.Indent(log.Warn, 2)("parsing private symbols...")
		// 	err = f.ParseLocalSyms()
		// 	if err != nil {
		// 		utils.Indent(log.Warn, 2)(err.Error())
		// 		utils.Indent(log.Warn, 2)("parsing patch exports...")
		// 		for _, img := range f.Images {
		// 			for _, patch := range img.PatchableExports {
		// 				addr, err := f.GetVMAddress(uint64(patch.OffsetOfImpl))
		// 				if err != nil {
		// 					return err
		// 				}
		// 				f.AddressToSymbol[addr] = patch.Name
		// 			}
		// 		}
		// 	}
		// 	// cache all sels
		// 	f.GetAllSelectors(false)
		// 	f.GetAllClasses(false)
		// 	f.GetAllProtocols(false)
		// 	// save lookup map to disk to speed up subsequent requests
		// 	err = f.SaveAddrToSymMap(dscPath + ".a2s")
		// 	if err != nil {
		// 		return err
		// 	}

		// } else {
		// 	log.Info("Found dyld_shared_cache companion symbol map file...")
		// 	a2sFile, err := os.Open(dscPath + ".a2s")
		// 	if err != nil {
		// 		return fmt.Errorf("failed to open companion file %s; %v", dscPath+".a2s", err)
		// 	}

		// 	gzr, err := gzip.NewReader(a2sFile)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to create gzip reader: %v", err)
		// 	}

		// 	// Decoding the serialized data
		// 	err = gob.NewDecoder(gzr).Decode(&f.AddressToSymbol)
		// 	if err != nil {
		// 		return fmt.Errorf("failed to decode addr2sym map; %v", err)
		// 	}
		// 	gzr.Close()
		// 	a2sFile.Close()
		// }
	retry:
		if showMapping {
			_, mapping, err := f.GetMappingForVMAddress(unslidAddr)
			if err != nil {
				return err
			}
			fmt.Printf("\nMAPPING\n")
			fmt.Printf("=======\n\n")
			fmt.Println(mapping.String())
		}

		image, err := f.GetImageContainingVMAddr(unslidAddr)
		if err != nil {
			return err
		}

		m, err := image.GetMacho()
		if err != nil {
			return err
		}
		defer m.Close()

		if showImage {
			fmt.Println("IMAGE")
			fmt.Println("-----")
			fmt.Printf(" > %s\n\n", image.Name)
		}

		if s := m.FindSegmentForVMAddr(unslidAddr); s != nil {
			if s.Nsect > 0 {
				if c := m.FindSectionForVMAddr(unslidAddr); c != nil {
					if showImage {
						fmt.Println(s)
						secFlags := ""
						if !c.Flags.IsRegular() {
							secFlags = fmt.Sprintf("(%s)", c.Flags)
						}
						fmt.Printf("\tsz=0x%08x off=0x%08x-0x%08x addr=0x%09x-0x%09x\t\t%s.%-20v%s %s\n", c.Size, c.Offset, uint64(c.Offset)+c.Size, c.Addr, c.Addr+c.Size, s.Name, c.Name, c.Flags.AttributesString(), secFlags)
					} else {
						log.WithFields(log.Fields{
							"dylib":   image.Name,
							"section": fmt.Sprintf("%s.%s", s.Name, c.Name),
						}).Info("Address location")
					}
				}
			} else {
				log.WithFields(log.Fields{
					"dylib":   image.Name,
					"segment": s.Name,
				}).Info("Address location")
			}
		}

		// Load all symbols
		if err := image.Analyze(); err != nil {
			return err
		}

		// TODO: add objc methods in the -[Class sel:] form
		if m.HasObjC() {
			log.Debug("Parsing ObjC runtime structures...")
			if err := f.CFStringsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc cfstrings")
			}
			if err := f.MethodsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc methods")
			}
			// if strings.Contains(image.Name, "libobjc.A.dylib") { // TODO: should I put this back in?
			// 	_, err = f.GetAllSelectors(false)
			// } else {
			if err := f.SelectorsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc selectors")
			}
			// }
			if err := f.ClassesForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc classes")
			}
			if err := f.ProtocolsForImage(image.Name); err != nil {
				return errors.Wrapf(err, "failed to parse objc protocols")
			}
		}

		if symName, ok := f.AddressToSymbol[unslidAddr]; ok {
			if secondAttempt {
				symName = "_ptr." + symName
			}
			fmt.Printf("\n%#x: %s\n", addr, symName)
			return nil
		}

		if fn, err := m.GetFunctionForVMAddr(unslidAddr); err == nil {
			delta := ""
			if unslidAddr-fn.StartAddr != 0 {
				delta = fmt.Sprintf(" + %d", unslidAddr-fn.StartAddr)
			}
			if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
				if secondAttempt {
					symName = "_ptr." + symName
				}
				fmt.Printf("\n%#x: %s%s\n", addr, symName, delta)
			} else {
				if secondAttempt {
					fmt.Printf("\n%#x: _ptr.func_%x%s\n", addr, fn.StartAddr, delta)
					return nil
				}
				fmt.Printf("\n%#x: func_%x%s\n", addr, fn.StartAddr, delta)
			}
			return nil
		}

		if cstr, ok := m.IsCString(unslidAddr); ok {
			if secondAttempt {
				fmt.Printf("\n%#x: _ptr.%#v\n", addr, cstr)
			} else {
				fmt.Printf("\n%#x: %#v\n", addr, cstr)
			}
			return nil
		}

		if secondAttempt {
			log.Error("no symbol found")
			return nil
		}

		ptr, err := f.ReadPointerAtAddress(unslidAddr)
		if err != nil {
			return err
		}

		utils.Indent(log.Error, 2)(fmt.Sprintf("no symbol found (trying again with %#x as a pointer to %#x)", unslidAddr, f.SlideInfo.SlidePointer(ptr)))

		unslidAddr = f.SlideInfo.SlidePointer(ptr)

		secondAttempt = true

		goto retry
	},
}
