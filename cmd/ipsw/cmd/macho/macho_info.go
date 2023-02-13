/*
Copyright © 2018-2023 blacktop

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
package macho

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alecthomas/chroma/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/certs"
	"github.com/blacktop/ipsw/internal/magic"
	swift "github.com/blacktop/ipsw/internal/swiftt"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/fullsailor/pkcs7"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	MachoCmd.AddCommand(machoInfoCmd)

	machoInfoCmd.Flags().StringP("arch", "a", "", "Which architecture to use for fat/universal MachO")
	machoInfoCmd.Flags().BoolP("header", "d", false, "Print the mach header")
	machoInfoCmd.Flags().BoolP("loads", "l", false, "Print the load commands")
	machoInfoCmd.Flags().BoolP("json", "j", false, "Print the TOC as JSON")
	machoInfoCmd.Flags().BoolP("sig", "s", false, "Print code signature")
	machoInfoCmd.Flags().BoolP("ent", "e", false, "Print entitlements")
	machoInfoCmd.Flags().BoolP("objc", "o", false, "Print ObjC info")
	machoInfoCmd.Flags().BoolP("objc-refs", "r", false, "Print ObjC references")
	machoInfoCmd.Flags().BoolP("symbols", "n", false, "Print symbols")
	machoInfoCmd.Flags().BoolP("strings", "c", false, "Print cstrings")
	machoInfoCmd.Flags().BoolP("starts", "f", false, "Print function starts")
	machoInfoCmd.Flags().BoolP("fixups", "u", false, "Print fixup chains")
	machoInfoCmd.Flags().BoolP("split-seg", "g", false, "Print split seg info")
	machoInfoCmd.Flags().StringP("fileset-entry", "t", "", "Which fileset entry to analyze")
	machoInfoCmd.Flags().BoolP("extract-fileset-entry", "x", false, "Extract the fileset entry")
	machoInfoCmd.Flags().BoolP("all-fileset-entries", "z", false, "Parse all fileset entries")
	machoInfoCmd.Flags().Bool("dump-cert", false, "Dump the certificate")
	machoInfoCmd.Flags().BoolP("bit-code", "b", false, "Dump the LLVM bitcode")
	machoInfoCmd.Flags().String("output", "", "Directory to extract files to")

	viper.BindPFlag("macho.info.arch", machoInfoCmd.Flags().Lookup("arch"))
	viper.BindPFlag("macho.info.header", machoInfoCmd.Flags().Lookup("header"))
	viper.BindPFlag("macho.info.loads", machoInfoCmd.Flags().Lookup("loads"))
	viper.BindPFlag("macho.info.json", machoInfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("macho.info.sig", machoInfoCmd.Flags().Lookup("sig"))
	viper.BindPFlag("macho.info.ent", machoInfoCmd.Flags().Lookup("ent"))
	viper.BindPFlag("macho.info.objc", machoInfoCmd.Flags().Lookup("objc"))
	viper.BindPFlag("macho.info.objc-refs", machoInfoCmd.Flags().Lookup("objc-refs"))
	viper.BindPFlag("macho.info.symbols", machoInfoCmd.Flags().Lookup("symbols"))
	viper.BindPFlag("macho.info.starts", machoInfoCmd.Flags().Lookup("starts"))
	viper.BindPFlag("macho.info.strings", machoInfoCmd.Flags().Lookup("strings"))
	viper.BindPFlag("macho.info.fixups", machoInfoCmd.Flags().Lookup("fixups"))
	viper.BindPFlag("macho.info.split-seg", machoInfoCmd.Flags().Lookup("split-seg"))
	viper.BindPFlag("macho.info.fileset-entry", machoInfoCmd.Flags().Lookup("fileset-entry"))
	viper.BindPFlag("macho.info.extract-fileset-entry", machoInfoCmd.Flags().Lookup("extract-fileset-entry"))
	viper.BindPFlag("macho.info.all-fileset-entries", machoInfoCmd.Flags().Lookup("all-fileset-entries"))
	viper.BindPFlag("macho.info.dump-cert", machoInfoCmd.Flags().Lookup("dump-cert"))
	viper.BindPFlag("macho.info.bit-code", machoInfoCmd.Flags().Lookup("bit-code"))
	viper.BindPFlag("macho.info.output", machoInfoCmd.Flags().Lookup("output"))

	machoInfoCmd.MarkZshCompPositionalArgumentFile(1)
}

// machoInfoCmd represents the macho command
var machoInfoCmd = &cobra.Command{
	Use:           "info <macho>",
	Aliases:       []string{"i"},
	Short:         "Explore a MachO file",
	Args:          cobra.MinimumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		var err error
		var m *macho.File

		if viper.GetBool("verbose") {
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
		showSplitSeg := viper.GetBool("macho.info.split-seg")
		filesetEntry := viper.GetString("macho.info.fileset-entry")
		extractfilesetEntry := viper.GetBool("macho.info.extract-fileset-entry")
		dumpCert := viper.GetBool("macho.info.dump-cert")
		dumpBitCode := viper.GetBool("macho.info.bit-code")
		extractPath := viper.GetString("macho.info.output")

		if len(filesetEntry) == 0 && extractfilesetEntry {
			return fmt.Errorf("you must supply a --fileset-entry|-t AND --extract-fileset-entry|-x to extract a file-set entry")
		}

		onlySig := !showHeader && !showLoadCommands && showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings && !showSplitSeg
		onlyEnt := !showHeader && !showLoadCommands && !showSignature && showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings && !showSplitSeg
		onlyFixups := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && showFixups && !showFuncStarts && !dumpStrings && !showSplitSeg
		onlyFuncStarts := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && showFuncStarts && !dumpStrings && !showSplitSeg
		onlyStrings := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && dumpStrings && !showSplitSeg
		onlySymbols := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && showSymbols && !showFixups && !showFuncStarts && !dumpStrings && !showSplitSeg
		onlyObjC := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings && !showSplitSeg
		onlySplitSegs := !showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings && showSplitSeg

		machoPath := filepath.Clean(args[0])

		if info, err := os.Stat(machoPath); os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", machoPath)
		} else if info.IsDir() {
			machoPath, err = plist.GetBinaryInApp(machoPath)
			if err != nil {
				return err
			}
		}

		if ok, err := magic.IsMachO(machoPath); !ok {
			return fmt.Errorf(err.Error())
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

		folder := filepath.Dir(machoPath) // default to folder of macho file
		if len(extractPath) > 0 {
			folder = extractPath
		}

		if dumpCert {
			if cs := m.CodeSignature(); cs != nil {
				if len(m.CodeSignature().CMSSignature) > 0 {
					// parse cert
					p7, err := pkcs7.Parse(m.CodeSignature().CMSSignature)
					if err != nil {
						return fmt.Errorf("failed to parse pkcs7: %v", err)
					}
					// create output file
					outPEM := filepath.Join(folder, filepath.Base(filepath.Clean(machoPath))+".pem")
					log.Infof("Created %s", outPEM)
					f, err := os.Create(outPEM)
					if err != nil {
						return fmt.Errorf("failed to create pem file %s: %v", outPEM, err)
					}
					defer f.Close()
					// write certs to file
					for _, cert := range p7.Certificates {
						if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
							return fmt.Errorf("failed to write pem file: %v", err)
						}
					}
				} else {
					return fmt.Errorf("no CMS signature found")
				}
				return nil
			} else {
				return fmt.Errorf("no LC_CODE_SIGNATURE found")
			}
		}

		if dumpBitCode {
			// NOTE: /opt/homebrew/opt/llvm/bin/llvm-dis 1.bc 2.bc 3.bc # to disassemble bitcode
			xr, err := m.GetEmbeddedLLVMBitcode()
			if err != nil {
				return fmt.Errorf("failed to get embedded llvm bitcode: %v", err)
			}
			reverse := func(arr []string) []string {
				reversed := make([]string, len(arr))
				j := 0
				for i := len(arr) - 1; i >= 0; i-- {
					reversed[j] = arr[i]
					j++
				}
				return reversed
			}
			sd := xr.Subdoc()
			var lo string
			for i, l := range reverse(sd.LinkOptions) {
				if i == 0 {
					lo = "    " + l
				} else if strings.HasPrefix(l, "-") {
					lo += "\n    " + l
				} else {
					lo += " " + l
				}
			}
			var ds []string
			for _, d := range reverse(sd.Dylibs) {
				ds = append(ds, fmt.Sprintf("    %s", d))
			}
			fmt.Printf(
				"LLVM Bitcode:\n"+
					"  Name:      %s\n"+
					"  Version:   %s\n"+
					"  Platform:  %s\n"+
					"  Arch:      %s\n"+
					"  SDK:       %s\n"+
					"  Hide Syms: %d\n"+
					"  Linker Options:\n"+
					"%s\n"+
					"  Dylibs:\n"+
					"%s\n\n",
				sd.Name,
				sd.Version,
				sd.Platform,
				sd.Arch,
				sd.SDKVersion,
				sd.HideSymbols,
				lo,
				strings.Join(ds, "\n"),
			)
			if xr.HasSignature() {
				log.Infof("Found embedded llvm bitcode signature")
				for _, cert := range xr.Certificates {
					fmt.Println(cert)
				}
			}
			if err := os.MkdirAll(folder, 0755); err != nil {
				return fmt.Errorf("failed to create folder %s: %v", folder, err)
			}
			toc := xr.TOC()
			for idx, xf := range xr.File {
				f, err := xf.Open()
				if err != nil {
					return fmt.Errorf("failed to open xar file: %v", err)
				}
				data, err := io.ReadAll(f)
				if err != nil {
					return fmt.Errorf("failed to read xar file: %v", err)
				}
				log.Infof("%s: %s", toc.File[idx-1].FileType, strings.Join(reverse(toc.File[idx-1].ClangArgs), " "))
				utils.Indent(log.Info, 2)("Extracting " + filepath.Join(folder, xf.Name+".bc"))
				if err := os.WriteFile(filepath.Join(folder, xf.Name+".bc"), data, 0644); err != nil {
					return fmt.Errorf("failed to write bitcode file: %v", err)
				}
				f.Close()
			}
			return nil
		}

		// Fileset MachO type
		if len(filesetEntry) > 0 {
			if m.FileTOC.FileHeader.Type == types.MH_FILESET {
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
					if err := m.Export(filepath.Join(folder, filesetEntry), dcf, baseAddress, nil); err != nil { // TODO: do I want to add any extra syms?
						return fmt.Errorf("failed to export entry MachO %s; %v", filesetEntry, err)
					}
					log.Infof("Created %s", filepath.Join(folder, filesetEntry))
				}
			} else {
				log.Error("MachO type is not MH_FILESET (cannot use --fileset-entry)")
			}
		} else if viper.GetBool("macho.info.all-fileset-entries") {
			if m.FileTOC.FileHeader.Type == types.MH_FILESET {
				for _, fe := range m.FileSets() {
					mfe, err := m.GetFileSetFileByName(fe.EntryID)
					if err != nil {
						return fmt.Errorf("failed to parse entry %s: %v", filesetEntry, err)
					}
					fmt.Printf("\n%s\n\n%s\n", fe.EntryID, mfe.FileTOC.String())
				}
			} else {
				return fmt.Errorf("MachO type is not MH_FILESET (cannot use --fileset-entry)")
			}
		}

		if showHeader && !showLoadCommands {
			fmt.Println(m.FileHeader.String())
		}
		if showLoadCommands || (!showHeader && !showLoadCommands && !showSignature && !showEntitlements && !showObjC && !showSymbols && !showFixups && !showFuncStarts && !dumpStrings && !showSplitSeg) {
			if viper.GetBool("macho.info.json") {
				dat, err := m.FileTOC.MarshalJSON()
				if err != nil {
					return fmt.Errorf("failed to marshal MachO table of contents as JSON: %v", err)
				}
				fmt.Println(string(dat))
			} else {
				fmt.Println(m.FileTOC.String())
			}
		} else {
			if len(filesetEntry) == 0 && !viper.GetBool("macho.info.all-fileset-entries") {
				if m.FileTOC.FileHeader.Type == types.MH_FILESET {
					log.Warn("detected MH_FILESET MachO, you might want to use '--fileset-entry' to select a specific file-set entry")
				}
			}
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
						var platform string
						var execSegFlags string
						if len(cd.TeamID) > 0 {
							teamID = fmt.Sprintf("\tTeamID:      %s\n", cd.TeamID)
						}
						if cd.Header.Platform != 0 {
							platform = fmt.Sprintf("\tPlatform:    %s (%d)\n", cd.Header.Platform, cd.Header.Platform)
						}
						if cd.Header.ExecSegFlags > 0 {
							execSegFlags = fmt.Sprintf(" (%s)", cd.Header.ExecSegFlags)
						}
						fmt.Printf("Code Directory (%d bytes)\n", cd.Length)
						fmt.Printf("\tVersion:     %s%s\n"+
							"\tFlags:       %#x (%s)\n"+
							"\tCodeLimit:   %#x\n"+
							"\tIdentifier:  %s (@%#x)\n"+
							"%s"+
							"%s"+
							"\tCDHash:      %s (computed)\n"+
							"\t# of hashes: %d code (%d pages) + %d special\n"+
							"\tHashes @%d size: %d Type: %s\n",
							cd.Header.Version,
							execSegFlags,
							uint32(cd.Header.Flags),
							cd.Header.Flags,
							cd.Header.CodeLimit,
							cd.ID,
							cd.Header.IdentOffset,
							teamID,
							platform,
							cd.CDHash,
							cd.Header.NCodeSlots,
							int(math.Pow(2, float64(cd.Header.PageSize))),
							cd.Header.NSpecialSlots,
							cd.Header.HashOffset,
							cd.Header.HashSize,
							cd.Header.HashType)
						if viper.GetBool("verbose") {
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
					fmt.Printf("CMS (RFC3852) signature (%d bytes):\n", len(m.CodeSignature().CMSSignature))
					p7, err := pkcs7.Parse(m.CodeSignature().CMSSignature)
					if err != nil {
						return err
					}
					w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
					for _, cert := range p7.Certificates {
						if viper.GetBool("verbose") {
							fmt.Fprintf(w, "Certificate:\n")
							fmt.Fprintf(w, "\tData:\n")
							fmt.Fprintf(w, "\t\tVersion: %d (%#x)\n", cert.Version, cert.Version)
							fmt.Fprintf(w, "\t\tSerial Number: %d (%#x)\n", cert.SerialNumber, cert.SerialNumber)
							var extraIssuerInfo string
							for _, name := range cert.Issuer.Names {
								if name.Type.Equal(certs.OIDEmailAddress) {
									extraIssuerInfo = fmt.Sprintf(",email=%s", name.Value.(string))
								}
							}
							fmt.Fprintf(w, "\t\tIssuer: %s\n", cert.Issuer.String()+extraIssuerInfo)
							fmt.Fprintf(w, "\t\tValidity:\n")
							fmt.Fprintf(w, "\t\t\tNot Before: %s\n", cert.NotBefore.Format("Jan 2 15:04:05 2006 MST"))
							fmt.Fprintf(w, "\t\t\tNot After:  %s\n", cert.NotAfter.Format("Jan 2 15:04:05 2006 MST"))
							var extraSubjectInfo string
							for _, name := range cert.Subject.Names {
								if name.Type.Equal(certs.OIDEmailAddress) {
									extraSubjectInfo = fmt.Sprintf(",email=%s", name.Value.(string))
								}
							}
							fmt.Fprintf(w, "\t\tSubject: %s\n", cert.Subject.String()+extraSubjectInfo)
							fmt.Fprintf(w, "\t\tSubject Public Key Info:\n")
							fmt.Fprintf(w, "\t\t\tPublic Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
							switch key := cert.PublicKey.(type) {
							case *rsa.PublicKey:
								fmt.Fprintf(w, "\t\t\t\tPublic Key: (%d bits)\n", key.Size()*8) // convert bytes to bits
								fmt.Fprintf(w, "\t\t\t\tModulus: \n%s\n", certs.ReprData(key.N.Bytes(), 5, 14))
								fmt.Fprintf(w, "\t\t\t\tExponent: %d (%#x)\n", key.E, key.E)
							case *ecdsa.PublicKey:
								fmt.Fprintf(w, "\t\t\t\tPublic Key: (%d bits)\n", key.Params().BitSize)
								fmt.Fprintf(w, "\t\t\t\t NIST CURVE: %s\n", key.Params().Name)
							}
							fmt.Fprintf(w, "\tX509v3 Extensions:\n")
							for _, ext := range cert.Extensions {
								critical := ""
								if ext.Critical {
									critical = " (critical)"
								}
								if ext.Id.Equal(certs.OIDSubjectKeyId) {
									fmt.Fprintf(w, "\t\tSubject Key ID: %s\n\t\t\t%s\n", critical, certs.ReprData(cert.SubjectKeyId, 0, len(cert.SubjectKeyId)+1))
								} else if ext.Id.Equal(certs.OIDKeyUsage) {
									fmt.Fprintf(w, "\t\tKey Usage: %s\n\t\t\t%s\n", critical, certs.KeyUsage(cert.KeyUsage).String())
								} else if ext.Id.Equal(certs.OIDExtendedKeyUsage) {
									var exu []string
									for _, e := range cert.ExtKeyUsage {
										exu = append(exu, certs.ExtKeyUsage(e).String())
									}
									fmt.Fprintf(w, "\t\tExtended Key Usage: %s\n\t\t\t%s\n", critical, strings.Join(exu, ", "))
								} else if ext.Id.Equal(certs.OIDAuthorityKeyId) {
									fmt.Fprintf(w, "\t\tAuthority Key ID: %s\n\t\t\tkeyid:%s\n", critical, certs.ReprData(cert.AuthorityKeyId, 0, len(cert.AuthorityKeyId)+1))
								} else if ext.Id.Equal(certs.OIDBasicConstraints) {
									var bconst string
									if cert.IsCA {
										bconst += "CA:TRUE"
									} else {
										bconst += "CA:FALSE"
									}
									fmt.Fprintf(w, "\t\tBasic Constraints: %s\n\t\t\t%s\n", critical, bconst)
								} else if ext.Id.Equal(certs.OIDSubjectAltName) {
									fmt.Fprintf(w, "\t\tSubject Alt Name: %s\n%s", critical, utils.HexDump(ext.Value, 0))
								} else if ext.Id.Equal(certs.OIDCertificatePolicies) {
									var policies []string
									for _, p := range cert.PolicyIdentifiers {
										if p.Equal(certs.OIDAppleCertificatePolicy) {
											policies = append(policies, "\t\t\tApple Certificate Policy")
										} else {
											policies = append(policies, fmt.Sprintf("\t\t\tUnknown (%s)", p.String()))
										}
									}
									fmt.Fprintf(w, "\t\tCertificate Policies: %s\n%s\n", critical, strings.Join(policies, "\n"))
								} else if ext.Id.Equal(certs.OIDNameConstraints) {
									fmt.Fprintf(w, "\t\tName Constraints: %s\n%s", critical, utils.HexDump(ext.Value, 0))
								} else if ext.Id.Equal(certs.OIDCRLDistributionPoints) {
									fmt.Fprintf(w, "\t\tCRL Distribution Points: %s\n\t\t\t%s\n", critical, strings.Join(cert.CRLDistributionPoints, ", "))
								} else if ext.Id.Equal(certs.OIDAuthorityInfoAccess) {
									var auths []string
									for _, a := range cert.OCSPServer {
										auths = append(auths, fmt.Sprintf("\t\t\tOCSP: %s", a))
									}
									fmt.Fprintf(w, "\t\tAuthority Info Access: %s\n%s\n", critical, strings.Join(auths, "\n"))
								} else if ext.Id.Equal(certs.OIDCRLNumber) {
									fmt.Fprintf(w, "\t\tCRL Number: %s\n%s", critical, utils.HexDump(ext.Value, 0))
								} else {
									fmt.Fprintf(w, "\t\t%s: %s\n%s\n", certs.LookupOID(ext.Id), critical, utils.HexDump(ext.Value, 0))
								}
							}
							fmt.Fprintf(w, "\tSignature (algorithm - %s): \n%s\n", cert.SignatureAlgorithm, certs.ReprData(cert.Signature, 2, 18))
							publicKeyBlock := pem.Block{
								Type:  "CERTIFICATE",
								Bytes: cert.Raw,
							}
							publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
							fmt.Fprintf(w, "\n%s\n", publicKeyPem)
							fmt.Println()
							utils.PrintCMSData(m.CodeSignature().CMSSignature)
						} else {
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
								cert.NotBefore.Format("02Jan2006 15:04:05"),
								cert.NotAfter.Format("02Jan2006 15:04:05"))
						}

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
			if !onlyObjC {
				fmt.Println("Objective-C")
				fmt.Println("===========")
			}
			if m.HasObjC() {
				if info, err := m.GetObjCImageInfo(); err == nil {
					fmt.Println(info.Flags)
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
				if viper.GetBool("verbose") {
					fmt.Println(m.GetObjCToc())
				}
				if protos, err := m.GetObjCProtocols(); err == nil {
					for _, proto := range protos {
						if viper.GetBool("verbose") {
							if viper.GetBool("color") {
								quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", "nord")
								quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", "nord")
							} else {
								fmt.Println(swift.DemangleBlob(proto.Verbose()))
							}
						} else {
							if viper.GetBool("color") {
								quick.Highlight(os.Stdout, proto.String()+"\n", "objc", "terminal256", "nord")
							} else {
								fmt.Println(proto.String())
							}
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
				if classes, err := m.GetObjCClasses(); err == nil {
					for _, class := range classes {
						if viper.GetBool("verbose") {
							if viper.GetBool("color") {
								quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", "nord")
								quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", "nord")
							} else {
								fmt.Println(swift.DemangleBlob(class.Verbose()))
							}
						} else {
							if viper.GetBool("color") {
								quick.Highlight(os.Stdout, class.String()+"\n", "objc", "terminal256", "nord")
							} else {
								fmt.Println(class.String())
							}
						}
					}
				} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					log.Error(err.Error())
				}
				if cats, err := m.GetObjCCategories(); err == nil {
					for _, cat := range cats {
						if viper.GetBool("verbose") {
							if viper.GetBool("color") {
								quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", "nord")
								quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", "nord")
							} else {
								fmt.Println(swift.DemangleBlob(cat.Verbose()))
							}
						} else {
							if viper.GetBool("color") {
								quick.Highlight(os.Stdout, cat.String()+"\n", "objc", "terminal256", "nord")
							} else {
								fmt.Println(cat.String())
							}
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
							// if viper.GetBool("verbose") {
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
					if viper.GetBool("verbose") {
						if classes, err := m.GetObjCClassNames(); err == nil {
							fmt.Printf("\n@objc_classname\n")
							for vmaddr, className := range classes {
								fmt.Printf("0x%011x: %s\n", vmaddr, className)
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
						}
						if methods, err := m.GetObjCMethodNames(); err == nil {
							fmt.Printf("\n@objc_methname\n")
							for vmaddr, method := range methods {
								fmt.Printf("0x%011x: %s\n", vmaddr, method)
							}
						} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
							log.Error(err.Error())
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
					if viper.GetBool("verbose") {
						fmt.Printf("%#016x-%#016x\n", fn.StartAddr, fn.EndAddr)
					} else {
						fmt.Printf("0x%016X\n", fn.StartAddr)
					}
				}
			} else {
				fmt.Println("  - no function starts")
			}
		}

		if showSymbols {
			if !onlySymbols {
				fmt.Println("SYMBOLS")
				fmt.Println("=======")
			}
			var sec string
			var label string
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
			if m.Symtab != nil {
				label = "Symtab"
				fmt.Printf("\n%s\n", label)
				fmt.Println(strings.Repeat("-", len(label)))
				for _, sym := range m.Symtab.Syms {
					if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
						sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
					}
					var lib string
					if sym.Desc.GetLibraryOrdinal() != types.SELF_LIBRARY_ORDINAL && sym.Desc.GetLibraryOrdinal() < types.MAX_LIBRARY_ORDINAL {
						lib = fmt.Sprintf("\t(%s)", filepath.Base(m.ImportedLibraries()[sym.Desc.GetLibraryOrdinal()-1]))
					}
					if viper.GetBool("verbose") {
						if sym.Value == 0 {
							fmt.Fprintf(w, "              <%s> [%s]\t%s%s\n", sym.Type.String(sec), sym.Desc, sym.Name, lib)
						} else {
							fmt.Fprintf(w, "%#09x:  <%s> [%s]\t%s%s\n", sym.Value, sym.Type.String(sec), sym.Desc, sym.Name, lib)
						}
					} else {
						if sym.Value == 0 {
							fmt.Fprintf(w, "              <%s>\t%s%s\n", sym.Type.String(sec), sym.Name, lib)
						} else {
							fmt.Fprintf(w, "%#09x:  <%s>\t%s%s\n", sym.Value, sym.Type.String(sec), sym.Name, lib)
						}
					}
				}
				w.Flush()
			} else {
				fmt.Println("  - no symbol table")
			}
			if binds, err := m.GetBindInfo(); err == nil {
				label = "DyldInfo [Binds]"
				fmt.Printf("\n%s\n", label)
				fmt.Println(strings.Repeat("-", len(label)))
				for _, bind := range binds {
					fmt.Fprintf(w, "%#09x:\t%s\n", bind.Start+bind.Offset, bind)
				}
				w.Flush()
			}
			if rebases, err := m.GetRebaseInfo(); err == nil {
				label = "DyldInfo [Rebases]"
				fmt.Printf("\n%s\n", label)
				fmt.Println(strings.Repeat("-", len(label)))
				for _, rebase := range rebases {
					fmt.Fprintf(w, "%#09x:\t%s\n", rebase.Start+rebase.Offset, rebase)
				}
				w.Flush()
			}
			if exports, err := m.GetExports(); err == nil {
				label = "DyldInfo [Exports]"
				fmt.Printf("\n%s\n", label)
				fmt.Println(strings.Repeat("-", len(label)))
				for _, export := range exports {
					fmt.Fprintf(w, "%#09x:  <%s> \t %s\n", export.Address, export.Flags, export.Name)
				}
				w.Flush()
			}
			if m.DyldExportsTrie() != nil && m.DyldExportsTrie().Size > 0 {
				label = "Dyld Exports Trie"
				fmt.Printf("\n%s\n", label)
				fmt.Println(strings.Repeat("-", len(label)))
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
						var sec *types.Section
						var lastSec *types.Section
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

		if showSplitSeg {
			if !onlySplitSegs {
				fmt.Println("SEGMENT_SPLIT_INFO")
				fmt.Println("==================")
			}
			var sections []types.Section
			for _, l := range m.Loads {
				if s, ok := l.(*macho.Segment); ok {
					for j := uint32(0); j < s.Nsect; j++ {
						sections = append(sections, *m.Sections[j+s.Firstsect])
					}
				}
			}
			m.ForEachV2SplitSegReference(func(fromSectionIndex, fromSectionOffset, toSectionIndex, toSectionOffset uint64, kind types.SplitInfoKind) {
				var toSeg string
				var toName string
				var toAddr uint64
				if toSectionIndex > 0 {
					toSeg = sections[toSectionIndex-1].Seg
					toName = sections[toSectionIndex-1].Name
					toAddr = sections[toSectionIndex-1].Addr + fromSectionOffset
				} else {
					toSeg = "mach"
					toName = "header"
					toAddr = fromSectionOffset
				}
				fmt.Printf("%16s.%-16s %#08x  =>  %16s.%-16s %#08x\tkind(%s)\n",
					sections[fromSectionIndex-1].Seg,
					sections[fromSectionIndex-1].Name,
					sections[fromSectionIndex-1].Addr+fromSectionOffset,
					toSeg,
					toName,
					toAddr,
					kind)
			})
		}

		if dumpStrings {
			if !onlyStrings {
				fmt.Println("STRINGS")
				fmt.Println("=======")
			}
			for _, sec := range m.Sections {
				if sec.Flags.IsCstringLiterals() || sec.Seg == "__TEXT" && sec.Name == "__const" {
					off, err := m.GetOffset(sec.Addr)
					if err != nil {
						return fmt.Errorf("failed to get offset for %s.%s: %v", sec.Seg, sec.Name, err)
					}
					dat := make([]byte, sec.Size)
					if _, err = m.ReadAt(dat, int64(off)); err != nil {
						return fmt.Errorf("failed to read cstring data in %s.%s: %v", sec.Seg, sec.Name, err)
					}

					csr := bytes.NewBuffer(dat)

					for {
						pos := sec.Addr + uint64(csr.Cap()-csr.Len())

						s, err := csr.ReadString('\x00')

						if err == io.EOF {
							break
						}

						if err != nil {
							return fmt.Errorf("failed to read string: %v", err)
						}

						s = strings.Trim(s, "\x00")

						if len(s) > 0 {
							if (sec.Seg == "__TEXT" && sec.Name == "__const") && !utils.IsASCII(s) {
								continue // skip non-ascii strings when dumping __TEXT.__const
							}
							fmt.Printf("%#x: %#v\n", pos, s)
						}
					}
				}
			}
			if cfstrs, err := m.GetCFStrings(); err == nil {
				if len(cfstrs) > 0 {
					fmt.Printf("\nCFStrings\n")
					fmt.Println("---------")
					for _, cfstr := range cfstrs {
						fmt.Printf("%#09x:  %#v\n", cfstr.Address, cfstr.Name)
					}
				}
			}
		}

		return nil
	},
}
