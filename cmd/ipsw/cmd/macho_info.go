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
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/fullsailor/pkcs7"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	machoCmd.AddCommand(machoInfoCmd)

	machoInfoCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	machoInfoCmd.Flags().BoolP("header", "d", false, "Print the mach header")
	machoInfoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	machoInfoCmd.Flags().BoolP("sig", "s", false, "Print code signature")
	machoInfoCmd.Flags().BoolP("ent", "e", false, "Print entitlements")
	machoInfoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	machoInfoCmd.Flags().BoolP("objc-refs", "r", false, "Print ObjC references")
	machoInfoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	machoInfoCmd.Flags().BoolP("strings", "c", false, "Print cstrings")
	machoInfoCmd.Flags().BoolP("starts", "f", false, "Print function starts")
	machoInfoCmd.Flags().BoolP("fixups", "u", false, "Print fixup chains")
	machoInfoCmd.Flags().StringP("fileset-entry", "t", "", "Which fileset entry to analyze")
	machoInfoCmd.Flags().BoolP("extract-fileset-entry", "x", false, "Extract the fileset entry")
	machoInfoCmd.MarkZshCompPositionalArgumentFile(1)
	viper.BindPFlag("macho.info.arch", machoInfoCmd.Flags().Lookup("arch"))
	viper.BindPFlag("macho.info.header", machoInfoCmd.Flags().Lookup("header"))
	viper.BindPFlag("macho.info.loads", machoInfoCmd.Flags().Lookup("loads"))
	viper.BindPFlag("macho.info.sig", machoInfoCmd.Flags().Lookup("sig"))
	viper.BindPFlag("macho.info.ent", machoInfoCmd.Flags().Lookup("ent"))
	viper.BindPFlag("macho.info.objc", machoInfoCmd.Flags().Lookup("objc"))
	viper.BindPFlag("macho.info.objc-refs", machoInfoCmd.Flags().Lookup("objc-refs"))
	viper.BindPFlag("macho.info.symbols", machoInfoCmd.Flags().Lookup("symbols"))
	viper.BindPFlag("macho.info.starts", machoInfoCmd.Flags().Lookup("starts"))
	viper.BindPFlag("macho.info.strings", machoInfoCmd.Flags().Lookup("strings"))
	viper.BindPFlag("macho.info.fixups", machoInfoCmd.Flags().Lookup("fixups"))
	viper.BindPFlag("macho.info.fileset-entry", machoInfoCmd.Flags().Lookup("fileset-entry"))
	viper.BindPFlag("macho.info.extract-fileset-entry", machoInfoCmd.Flags().Lookup("extract-fileset-entry"))
}

// machoInfoCmd represents the macho command
var machoInfoCmd = &cobra.Command{
	Use:          "info <macho>",
	Short:        "Explore a MachO file",
	Args:         cobra.MinimumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		var err error

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		// flags
		selectedArch := viper.GetString("macho.info.arch")
		showHeader := viper.GetBool("macho.info.header")
		showLoadCommands := viper.GetBool("macho.info.loads")
		showSignature := viper.GetBool("macho.info.sig")
		showEntitlements := viper.GetBool("macho.info.ent")
		showObjC := viper.GetBool("macho.info.objc")
		showObjcRefs := viper.GetBool("macho.info.objc-refs")
		showSymbols := viper.GetBool("macho.info.symbols")
		showFuncStarts := viper.GetBool("macho.info.starts")
		dumpStrings := viper.GetBool("macho.info.strings")
		showFixups := viper.GetBool("macho.info.fixups")
		filesetEntry := viper.GetString("macho.info.fileset-entry")
		extractfilesetEntry := viper.GetBool("macho.info.extract-fileset-entry")

		if len(filesetEntry) == 0 && extractfilesetEntry {
			return fmt.Errorf("you must supply a --fileset-entry|-t AND --extract-fileset-entry|-x to extract a file-set entry")
		}

		onlySig := !showHeader && !showLoadCommands && showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings
		onlyEnt := !showHeader && !showLoadCommands && !showSignature && showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings
		onlyFixups := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && showFixups && !showFuncStarts && !dumpStrings
		onlyFuncStarts := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && showFuncStarts && !dumpStrings
		onlyStrings := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && dumpStrings
		onlySymbols := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && showSymbols && !showFixups && !showFuncStarts && !dumpStrings

		machoPath := filepath.Clean(args[0])

		if _, err := os.Stat(machoPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", machoPath)
		}

		// first check for fat file
		fat, err := macho.OpenFat(machoPath)
		if err != nil && err != macho.ErrNotFat {
			return err
		}
		if err == macho.ErrNotFat {
			m, err = macho.Open(machoPath)
			if err != nil {
				return err
			}
		} else {
			var options []string
			var shortOptions []string
			for _, arch := range fat.Arches {
				options = append(options, fmt.Sprintf("%s, %s", arch.CPU, arch.SubCPU.String(arch.CPU)))
				shortOptions = append(shortOptions, strings.ToLower(arch.SubCPU.String(arch.CPU)))
			}

			if len(selectedArch) > 0 {
				found := false
				for i, opt := range shortOptions {
					if strings.Contains(strings.ToLower(opt), strings.ToLower(selectedArch)) {
						m = fat.Arches[i].File
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("--arch '%s' not found in: %s", selectedArch, strings.Join(shortOptions, ", "))
				}
			} else {
				choice := 0
				prompt := &survey.Select{
					Message: "Detected a universal MachO file, please select an architecture to analyze:",
					Options: options,
				}
				survey.AskOne(prompt, &choice)
				m = fat.Arches[choice].File
			}
		}

		// Fileset MachO type
		if len(filesetEntry) > 0 {
			if m.FileTOC.FileHeader.Type == types.FileSet {
				var dcf *fixupchains.DyldChainedFixups
				if m.HasFixups() {
					dcf, err = m.DyldChainedFixups()
					if err != nil {
						return fmt.Errorf("failed to parse fixups from in memory MachO: %v", err)
					}
				}

				baseAddress := m.GetBaseAddress()
				m, err = m.GetFileSetFileByName(filesetEntry)
				if err != nil {
					return fmt.Errorf("failed to parse entry %s: %v", filesetEntry, err)
				}

				if extractfilesetEntry {
					err = m.Export(filepath.Join(filepath.Dir(machoPath), filesetEntry), dcf, baseAddress, nil) // TODO: do I want to add any extra syms?
					if err != nil {
						return fmt.Errorf("failed to export entry MachO %s; %v", filesetEntry, err)
					}
					log.Infof("Created %s", filepath.Join(filepath.Dir(machoPath), filesetEntry))
				}

			} else {
				log.Error("MachO type is not FileSet")
				return nil
			}
		}

		if showHeader && !showLoadCommands {
			fmt.Println(m.FileHeader.String())
		}
		if showLoadCommands || (!showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings) {
			fmt.Println(m.FileTOC.String())
		}

		if showSignature {
			if !onlySig {
				fmt.Println("Code Signature")
				fmt.Println("==============")
			}
			if m.CodeSignature() != nil {
				cds := m.CodeSignature().CodeDirectories
				if len(cds) > 0 {
					for _, cd := range cds {
						var teamID string
						var execSegFlags string
						if len(cd.TeamID) > 0 {
							teamID = fmt.Sprintf("\tTeamID:      %s\n", cd.TeamID)
						}
						if cd.Header.ExecSegFlags > 0 {
							execSegFlags = fmt.Sprintf(" (%s)", cd.Header.ExecSegFlags.String())
						}
						fmt.Printf("Code Directory (%d bytes)\n", cd.Header.Length)
						fmt.Printf("\tVersion:     %s%s\n"+
							"\tFlags:       %s\n"+
							"\tCodeLimit:   %#x\n"+
							"\tIdentifier:  %s (@%#x)\n"+
							"%s"+
							"\tCDHash:      %s (computed)\n"+
							"\t# of hashes: %d code (%d pages) + %d special\n"+
							"\tHashes @%d size: %d Type: %s\n",
							cd.Header.Version,
							execSegFlags,
							cd.Header.Flags,
							cd.Header.CodeLimit,
							cd.ID,
							cd.Header.IdentOffset,
							teamID,
							cd.CDHash,
							cd.Header.NCodeSlots,
							int(math.Pow(2, float64(cd.Header.PageSize))),
							cd.Header.NSpecialSlots,
							cd.Header.HashOffset,
							cd.Header.HashSize,
							cd.Header.HashType)
						if Verbose {
							for _, sslot := range cd.SpecialSlots {
								fmt.Printf("\t\t%s\n", sslot.Desc)
							}
							for _, cslot := range cd.CodeSlots {
								fmt.Printf("\t\t%s\n", cslot.Desc)
							}
						}
					}
				}
				reqs := m.CodeSignature().Requirements
				if len(reqs) > 0 {
					fmt.Printf("Requirement Set (%d bytes) with %d requirement\n",
						reqs[0].Length, // TODO: fix this (needs to be length - sizeof(header))
						len(reqs))
					for idx, req := range reqs {
						fmt.Printf("\t%d: %s (@%d, %d bytes): %s\n",
							idx,
							req.Type,
							req.Offset,
							req.Length,
							req.Detail)
					}
				}
				if len(m.CodeSignature().CMSSignature) > 0 {
					fmt.Println("CMS (RFC3852) signature:")
					p7, err := pkcs7.Parse(m.CodeSignature().CMSSignature)
					if err != nil {
						return err
					}
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
					for _, cert := range p7.Certificates {
						var ou string
						if cert.Issuer.Organization != nil {
							ou = cert.Issuer.Organization[0]
						}
						if cert.Issuer.OrganizationalUnit != nil {
							ou = cert.Issuer.OrganizationalUnit[0]
						}
						fmt.Fprintf(w, "        OU: %s\tCN: %s\t(%s thru %s)\n",
							ou,
							cert.Subject.CommonName,
							cert.NotBefore.Format("01Jan06 15:04:05"),
							cert.NotAfter.Format("01Jan06 15:04:05"))
					}
					w.Flush()
				}
			} else {
				fmt.Println("  - no code signature data")
			}
			fmt.Println()
		}

		if showEntitlements {
			if !onlyEnt {
				fmt.Println("Entitlements")
				fmt.Println("============")
			}
			if m.CodeSignature() != nil && len(m.CodeSignature().Entitlements) > 0 {
				fmt.Println(m.CodeSignature().Entitlements)
			} else {
				fmt.Println("  - no entitlements")
			}
		}

		if showObjC {
			fmt.Println("Objective-C")
			fmt.Println("===========")
			if m.HasObjC() {
				if info, err := m.GetObjCImageInfo(); err == nil {
					fmt.Println(info.Flags)
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
				if Verbose {
					fmt.Println(m.GetObjCToc())
				}
				if protos, err := m.GetObjCProtocols(); err == nil {
					for _, proto := range protos {
						if Verbose {
							fmt.Println(proto.Verbose())
						} else {
							fmt.Println(proto.String())
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
				if classes, err := m.GetObjCClasses(); err == nil {
					for _, class := range classes {
						if Verbose {
							fmt.Println(class.Verbose())
						} else {
							fmt.Println(class.String())
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
				if cats, err := m.GetObjCCategories(); err == nil {
					for _, cat := range cats {
						if Verbose {
							fmt.Println(cat.Verbose())
						} else {
							fmt.Println(cat.String())
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
				if showObjcRefs {
					if protRefs, err := m.GetObjCProtoReferences(); err == nil {
						fmt.Printf("\n@protocol refs\n")
						for off, prot := range protRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, prot.Ptr, prot.Name)
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
					if clsRefs, err := m.GetObjCClassReferences(); err == nil {
						fmt.Printf("\n@class refs\n")
						for off, cls := range clsRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, cls.ClassPtr, cls.Name)
							// if Verbose {
							// 	fmt.Println(cls.Verbose())
							// } else {
							// 	fmt.Println(cls.String())
							// }
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
					if supRefs, err := m.GetObjCSuperReferences(); err == nil {
						fmt.Printf("\n@super refs\n")
						for off, sup := range supRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, sup.ClassPtr, sup.Name)
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
					if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
						fmt.Printf("\n@selectors refs\n")
						for off, sel := range selRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, sel.VMAddr, sel.Name)
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
					if methods, err := m.GetObjCMethodNames(); err == nil {
						fmt.Printf("\n@methods\n")
						for method, vmaddr := range methods {
							fmt.Printf("0x%011x: %s\n", vmaddr, method)
						}
					} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
						log.Error(err.Error())
					}
				}

			} else {
				fmt.Println("  - no objc")
			}
			fmt.Println()
		}

		if showFuncStarts {
			if !onlyFuncStarts {
				fmt.Println("FUNCTION STARTS")
				fmt.Println("===============")
			}
			if m.FunctionStarts() != nil {
				for _, fn := range m.GetFunctions() {
					if Verbose {
						fmt.Printf("%#016x-%#016x\n", fn.StartAddr, fn.EndAddr)
					} else {
						fmt.Printf("0x%016X\n", fn.StartAddr)
					}
				}
			}
		}

		if showSymbols {
			if !onlySymbols {
				fmt.Println("SYMBOLS")
				fmt.Println("=======")
			}
			var sec string
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			for _, sym := range m.Symtab.Syms {
				if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
					sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
				}
				fmt.Fprintf(w, "%#09x:  <%s> \t %s\n", sym.Value, sym.Type.String(sec), sym.Name)
				// fmt.Printf("0x%016X <%s> %s\n", sym.Value, sym.Type.String(sec), sym.Name)
			}
			w.Flush()
			if binds, err := m.GetBindInfo(); err == nil {
				fmt.Printf("\nDyld Binds\n")
				fmt.Println("----------")
				for _, bind := range binds {
					fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.Offset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
				}
				w.Flush()
			}
			// Dedup these symbols (has repeats but also additional symbols??)
			if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 && Verbose {
				fmt.Printf("\nDyld Exports\n")
				fmt.Println("------------")
				exports, err := m.DyldExports()
				if err != nil {
					return err
				}
				for _, export := range exports {
					fmt.Fprintf(w, "%#09x:  <%s> \t %s\n", export.Address, export.Flags, export.Name)
				}
				w.Flush()
			}
		}

		if showFixups {
			if !onlyFixups {
				fmt.Println("FIXUPS")
				fmt.Println("======")
			}
			if m.HasFixups() {

				dcf, err := m.DyldChainedFixups()
				if err != nil {
					return err
				}

				for _, start := range dcf.Starts {
					if start.PageStarts != nil {
						var sec *macho.Section
						var lastSec *macho.Section
						for _, fixup := range start.Fixups {
							switch f := fixup.(type) {
							case fixupchains.Bind:
								var addend string
								addr := uint64(f.Offset()) + m.GetBaseAddress()
								if fullAddend := dcf.Imports[f.Ordinal()].Addend() + f.Addend(); fullAddend > 0 {
									addend = fmt.Sprintf(" + 0x%x", fullAddend)
									addr += fullAddend
								}
								sec = m.FindSectionForVMAddr(addr)
								lib := m.LibraryOrdinalName(dcf.Imports[f.Ordinal()].LibOrdinal())
								if sec != nil && sec != lastSec {
									fmt.Printf("%s.%s\n", sec.Seg, sec.Name)
								}
								fmt.Printf("%s\t%s/%s%s\n", fixupchains.Bind(f).String(m.GetBaseAddress()), lib, f.Name(), addend)
							case fixupchains.Rebase:
								addr := uint64(f.Offset()) + m.GetBaseAddress()
								sec = m.FindSectionForVMAddr(addr)
								if sec != nil && sec != lastSec {
									fmt.Printf("%s.%s\n", sec.Seg, sec.Name)
								}
								fmt.Println(f.String(m.GetBaseAddress()))
							}
							lastSec = sec
						}
					}
				}
			} else {
				fmt.Println("  - no fixups")
			}
		}

		if dumpStrings {
			if !onlyStrings {
				fmt.Println("STRINGS")
				fmt.Println("=======")
			}
			for _, sec := range m.Sections {
				if sec.Flags.IsCstringLiterals() {
					dat, err := sec.Data()
					if err != nil {
						return fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
					}

					csr := bytes.NewBuffer(dat[:])

					for {
						pos := sec.Addr + uint64(csr.Cap()-csr.Len())

						s, err := csr.ReadString('\x00')

						if err == io.EOF {
							break
						}

						if err != nil {
							return fmt.Errorf("failed to read string: %v", err)
						}

						if len(s) > 0 {
							fmt.Printf("%#x: %#v\n", pos, strings.Trim(s, "\x00"))
						}
					}
				}
			}
			if cfstrs, err := m.GetCFStrings(); err == nil {
				fmt.Printf("\nCFStrings\n")
				fmt.Println("---------")
				for _, cfstr := range cfstrs {
					fmt.Printf("%#09x:  %#v\n", cfstr.Address, cfstr.Name)
				}
			}
		}

		return nil
	},
}
