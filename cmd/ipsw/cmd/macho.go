/*
Copyright © 2019 blacktop

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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(machoCmd)

	machoCmd.Flags().StringP("arch", "a", viper.GetString("IPSW_ARCH"), "Which architecture to use for fat/universal MachO")
	machoCmd.Flags().BoolP("header", "d", false, "Print the mach header")
	machoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	machoCmd.Flags().BoolP("sig", "s", false, "Print code signature")
	machoCmd.Flags().BoolP("ent", "e", false, "Print entitlements")
	machoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	machoCmd.Flags().BoolP("objc-refs", "r", false, "Print ObjC references")
	machoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	machoCmd.Flags().BoolP("strings", "c", false, "Print cstrings")
	machoCmd.Flags().BoolP("starts", "f", false, "Print function starts")
	machoCmd.Flags().BoolP("fixups", "u", false, "Print fixup chains")
	machoCmd.Flags().StringP("fileset-entry", "t", viper.GetString("IPSW_FILESET_ENTRY"), "Which fileset entry to analyze")
	machoCmd.Flags().BoolP("extract-fileset-entry", "x", false, "Extract the fileset entry")
	machoCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoCmd represents the macho command
var machoCmd = &cobra.Command{
	Use:          "macho <macho_file>",
	Short:        "Parse a MachO file",
	Args:         cobra.MinimumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var m *macho.File
		var err error

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		selectedArch, _ := cmd.Flags().GetString("arch")
		showHeader, _ := cmd.Flags().GetBool("header")
		showLoadCommands, _ := cmd.Flags().GetBool("loads")
		showSignature, _ := cmd.Flags().GetBool("sig")
		showEntitlements, _ := cmd.Flags().GetBool("ent")
		showObjC, _ := cmd.Flags().GetBool("objc")
		showObjcRefs, _ := cmd.Flags().GetBool("objc-refs")
		showSymbols, _ := cmd.Flags().GetBool("symbols")
		showFuncStarts, _ := cmd.Flags().GetBool("starts")
		dumpStrings, _ := cmd.Flags().GetBool("strings")
		showFixups, _ := cmd.Flags().GetBool("fixups")
		filesetEntry, _ := cmd.Flags().GetString("fileset-entry")
		extractfilesetEntry, _ := cmd.Flags().GetBool("extract-fileset-entry")

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
					Message: "Detected a fat MachO file, please select an architecture to analyze:",
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
					err = m.Export(filepath.Join(filepath.Dir(machoPath), filesetEntry), dcf, baseAddress)
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
							execSegFlags = fmt.Sprintf(" (%s)\n", cd.Header.ExecSegFlags.String())
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
							cert.NotBefore.Format("2006-01-02"),
							cert.NotAfter.Format("2006-01-02"))
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
					// fmt.Println(m.GetObjCInfo())
					fmt.Println(info.Flags)
				}

				if protos, err := m.GetObjCProtocols(); err == nil {
					for _, proto := range protos {
						if Verbose {
							fmt.Println(proto.Verbose())
						} else {
							fmt.Println(proto.String())
						}
					}
				}
				if classes, err := m.GetObjCClasses(); err == nil {
					for _, class := range classes {
						if Verbose {
							fmt.Println(class.Verbose())
						} else {
							fmt.Println(class.String())
						}
					}
				} else {
					log.Error(err.Error())
				}
				if nlclasses, err := m.GetObjCPlusLoadClasses(); err == nil {
					for _, class := range nlclasses {
						if Verbose {
							fmt.Println(class.Verbose())
						} else {
							fmt.Println(class.String())
						}
					}
				}
				if cats, err := m.GetObjCCategories(); err == nil {
					for _, cat := range cats {
						if Verbose {
							fmt.Println(cat.Verbose())
						} else {
							fmt.Println(cat.String())
						}
					}
				}
				if showObjcRefs {
					if protRefs, err := m.GetObjCProtoReferences(); err == nil {
						fmt.Printf("\n@protocol refs\n")
						for off, prot := range protRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, prot.Ptr.VMAdder, prot.Name)
						}
					}
					if clsRefs, err := m.GetObjCClassReferences(); err == nil {
						fmt.Printf("\n@class refs\n")
						for off, cls := range clsRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, cls.ClassPtr.VMAdder, cls.Name)
							// if Verbose {
							// 	fmt.Println(cls.Verbose())
							// } else {
							// 	fmt.Println(cls.String())
							// }
						}
					}
					if supRefs, err := m.GetObjCSuperReferences(); err == nil {
						fmt.Printf("\n@super refs\n")
						for off, sup := range supRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, sup.ClassPtr.VMAdder, sup.Name)
						}
					}
					if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
						fmt.Printf("\n@selectors refs\n")
						for off, sel := range selRefs {
							fmt.Printf("0x%011x => 0x%011x: %s\n", off, sel.VMAddr, sel.Name)
						}
					}
					if methods, err := m.GetObjCMethodNames(); err == nil {
						fmt.Printf("\n@methods\n")
						for method, vmaddr := range methods {
							fmt.Printf("0x%011x: %s\n", vmaddr, method)
						}
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
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
			for _, sym := range m.Symtab.Syms {
				if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
					sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
				}
				fmt.Fprintf(w, "%#016x:  <%s> \t %s\n", sym.Value, sym.Type.String(sec), sym.Name)
				// fmt.Printf("0x%016X <%s> %s\n", sym.Value, sym.Type.String(sec), sym.Name)
			}
			w.Flush()
			// Dedup these symbols (has repeats but also additional symbols??)
			if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 {
				fmt.Println("DyldExport SYMBOLS")
				fmt.Println("------------------")
				exports, err := m.DyldExports()
				if err != nil {
					return err
				}
				for _, export := range exports {
					fmt.Fprintf(w, "%#016x:  <%s> \t %s\n", export.Address, export.Flags, export.Name)
				}
				w.Flush()
			}
			if cfstrs, err := m.GetCFStrings(); err == nil {
				fmt.Println("CFStrings")
				fmt.Println("---------")
				for _, cfstr := range cfstrs {
					fmt.Printf("%#016x:  %#v\n", cfstr.Address, cfstr.Name)
				}
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
		}

		return nil
	},
}
