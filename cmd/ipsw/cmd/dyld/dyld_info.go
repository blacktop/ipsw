/*
Copyright © 2018-2026 blacktop

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
package dyld

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	dscCmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fullsailor/pkcs7"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	DyldCmd.AddCommand(dyldInfoCmd)
	dyldInfoCmd.Flags().BoolP("closures", "c", false, "Dump program launch closures")
	dyldInfoCmd.Flags().BoolP("dlopen", "d", false, "Dump all dylibs and bundles with dlopen closures")
	dyldInfoCmd.Flags().BoolP("dylibs", "l", false, "List dylibs and their versions")
	dyldInfoCmd.Flags().BoolP("sig", "s", false, "Print code signature")
	dyldInfoCmd.Flags().BoolP("json", "j", false, "Output as JSON")
	dyldInfoCmd.Flags().Bool("diff", false, "Diff two DSCs' images (requires --dylibs)")
	dyldInfoCmd.Flags().Bool("delta", false, "Compare two DSCs' image versions (requires --dylibs)")
	viper.BindPFlag("dyld.info.closures", dyldInfoCmd.Flags().Lookup("closures"))
	viper.BindPFlag("dyld.info.dlopen", dyldInfoCmd.Flags().Lookup("dlopen"))
	viper.BindPFlag("dyld.info.dylibs", dyldInfoCmd.Flags().Lookup("dylibs"))
	viper.BindPFlag("dyld.info.sig", dyldInfoCmd.Flags().Lookup("sig"))
	viper.BindPFlag("dyld.info.json", dyldInfoCmd.Flags().Lookup("json"))
	viper.BindPFlag("dyld.info.diff", dyldInfoCmd.Flags().Lookup("diff"))
	viper.BindPFlag("dyld.info.delta", dyldInfoCmd.Flags().Lookup("delta"))
}

// dyldInfoCmd represents the info command
var dyldInfoCmd = &cobra.Command{
	Use:     "info <DSC> [DSC]",
	Aliases: []string{"i"},
	Short:   "Parse dyld_shared_cache",
	Long: `Parse a dyld_shared_cache. Use --dylibs with either --diff or --delta and
two caches to compare images from the first cache to the second. The comparison
modes are mutually exclusive. With --json, either mode emits sorted added,
removed, and changed image records with versions; an empty version means the
image has no source-version load command.`,
	Example: "  ipsw dyld info --dylibs --delta old/DSC new/DSC\n  ipsw dyld info --dylibs --diff --json old/DSC new/DSC",
	Args:    dyldInfoArgs,
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := dyldInfoArgs(cmd, args); err != nil {
			return err
		}

		// flags
		// showHeader := viper.GetBool("header")
		showDylibs := viper.GetBool("dyld.info.dylibs")
		showClosures := viper.GetBool("dyld.info.closures")
		showDlopenOthers := viper.GetBool("dyld.info.dlopen")
		showSignature := viper.GetBool("dyld.info.sig")
		outAsJSON := viper.GetBool("dyld.info.json")
		diff := viper.GetBool("dyld.info.diff")
		delta := viper.GetBool("dyld.info.delta")

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

		// TODO: check for
		// if ( dylibInfo->isAlias )
		//   	printf("[alias] %s\n", dylibInfo->path);

		f, err := dyld.Open(dscPath)
		if err != nil {
			return err
		}
		defer f.Close()

		var versions1, versions2 map[string]string
		var comparison dylibComparison
		if diff || delta {
			f2, err := dyld.Open(filepath.Clean(args[1]))
			if err != nil {
				return err
			}
			defer f2.Close()
			versions1, err = dylibVersions(f)
			if err != nil {
				return err
			}
			versions2, err = dylibVersions(f2)
			if err != nil {
				return err
			}
			comparison = compareDylibVersions(versions1, versions2)
			if outAsJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(comparison)
			}
		}

		if outAsJSON {
			dinfo, err := dscCmd.GetInfo(f)
			if err != nil {
				return fmt.Errorf("failed to get DSC info: %s", err)
			}
			j, err := json.Marshal(dinfo)
			if err != nil {
				return err
			}
			fmt.Println(string(j))
			return nil
		}

		if !diff && !delta {
			// print HEADER info
			fmt.Println(f.String(viper.GetBool("verbose")))
		}

		if showSignature {
			fmt.Println("Code Signature")
			fmt.Println("==============")
			if f.CodeSignatures != nil {
				for u, cs := range f.CodeSignatures {
					if f.IsDyld4 {
						fmt.Printf("\n> SubCache %s\n\n", u)
					}
					cds := cs.CodeDirectories
					if len(cds) > 0 {
						for _, cd := range cds {
							var teamID string
							if len(cd.TeamID) > 0 {
								teamID = fmt.Sprintf("\tTeamID:      %s\n", cd.TeamID)
							}
							fmt.Printf("Code Directory (%d bytes)\n", cd.Length)
							fmt.Printf("\tVersion:     %s\n"+
								"\tFlags:       %s\n"+
								"\tCodeLimit:   0x%x\n"+
								"\tIdentifier:  %s (@0x%x)\n"+
								"%s"+
								"\tCDHash:      %s (computed)\n"+
								"\t# of hashes: %d code (%d pages) + %d special\n"+
								"\tHashes @%d size: %d Type: %s\n",
								cd.Header.Version,
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
					reqs := cs.Requirements
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
					if len(cs.CMSSignature) > 0 {
						fmt.Println("CMS (RFC3852) signature:")
						p7, err := pkcs7.Parse(cs.CMSSignature)
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
								cert.NotBefore.Format("02Jan2006 15:04:05"),
								cert.NotAfter.Format("02Jan2006 15:04:05"))
						}
						w.Flush()
					}
				}
			} else {
				fmt.Println("  - no code signature data")
			}
			fmt.Println()
		}

		if showDylibs {
			if diff || delta {
				if delta {
					var new, gone []string
					for _, image := range comparison.Added {
						new = append(new, fmt.Sprintf("`%s`\t(%s)", image.Name, image.Version))
					}
					for _, image := range comparison.Removed {
						gone = append(gone, fmt.Sprintf("`%s`\t(%s)", image.Name, image.Version))
					}
					var diffs []utils.MachoVersion
					for _, image := range comparison.Changed {
						var verdiff string
						if image.OldVersion == "" || image.NewVersion == "" {
							verdiff = fmt.Sprintf("%q -> %q", image.OldVersion, image.NewVersion)
						} else {
							verdiff, err = utils.DiffVersion(image.NewVersion, image.OldVersion)
							if err != nil {
								return err
							}
						}
						diffs = append(diffs, utils.MachoVersion{Name: image.Name, Version: verdiff})
					}

					buf := bytes.NewBufferString("### 🆕 dylibs\n\n")
					for _, d := range new {
						buf.WriteString(fmt.Sprintf("- %s\n", d))
					}
					buf.WriteString("\n### ❌ removed dylibs\n\n")
					for _, d := range gone {
						buf.WriteString(fmt.Sprintf("- %s\n", d))
					}
					buf.WriteString("\n### ⬆️ (delta) updated dylibs\n\n")
					utils.SortMachoVersions(diffs)
					w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
					var prev string
					for _, d := range diffs {
						if len(prev) > 0 && prev != d.Version {
							fmt.Fprintf(w, "\n---\n\n")
						}
						fmt.Fprintf(w, "- (%s)\t`%s`  \n", d.Version, d.Name)
						prev = d.Version
					}
					w.Flush()

					if utils.ColorEnabled() {
						if err := quick.Highlight(os.Stdout, buf.String(), "md", "terminal256", "nord"); err != nil {
							return err
						}
					} else {
						fmt.Println(buf.String())
					}
				}

				if diff {
					var dout1, dout2 []string
					for name, version := range versions1 {
						dout1 = append(dout1, fmt.Sprintf("%s\t(%s)", name, version))
					}
					for name, version := range versions2 {
						dout2 = append(dout2, fmt.Sprintf("%s\t(%s)", name, version))
					}
					sort.Strings(dout1)
					sort.Strings(dout2)

					out, err := utils.GitDiff(
						strings.Join(dout1, "\n")+"\n",
						strings.Join(dout2, "\n")+"\n",
						&utils.GitDiffConfig{Color: utils.ColorEnabled(), Tool: viper.GetString("diff-tool")})
					if err != nil {
						return err
					}

					if len(out) == 0 {
						log.Info("No differences found")
					} else {
						log.Info("Differences found")
						fmt.Println(out)
					}
				}
			} else {
				fmt.Println("Images")
				fmt.Println("======")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				for idx, img := range f.Images {
					if f.Headers[f.UUID].FormatVersion.IsDylibsExpectedOnDisk() {
						m, err := macho.Open(img.Name)
						if err != nil {
							if serr, ok := err.(*macho.FormatError); !ok {
								return errors.Wrapf(serr, "failed to open MachO %s", img.Name)
							}
							fat, err := macho.OpenFat(img.Name)
							if err != nil {
								return errors.Wrapf(err, "failed to open Fat MachO %s", img.Name)
							}
							fmt.Fprintf(w, "%4d: %#x\t(%s)\t%s\n", idx+1, img.Info.Address, fat.Arches[0].SourceVersion().Version, img.Name)
							fat.Close()
							continue
						}
						if m.SourceVersion() != nil {
							fmt.Fprintf(w, "%4d: %#x\t(%s)\t%s\n", idx+1, img.Info.Address, m.SourceVersion().Version, img.Name)
						} else {
							fmt.Fprintf(w, "%4d: %#x\t(%s)\t%s\n", idx+1, img.Info.Address, "No SourceVersion", img.Name)
						}
						m.Close()
					} else {
						m, err := img.GetPartialMacho()
						if err != nil {
							return fmt.Errorf("failed to create partial MachO for image %s: %v", img.Name, err)
						}
						srcVer := "No SourceVersion"
						if m.SourceVersion() != nil {
							srcVer = m.SourceVersion().Version.String()
						}
						if viper.GetBool("verbose") {
							fmt.Fprintf(w, "%4d: %#x\t%s\t(%s)\t%s\n", idx+1, img.Info.Address, m.UUID(), srcVer, img.Name)
						} else {
							fmt.Fprintf(w, "%4d: (%s)\t%s\n", idx+1, srcVer, img.Name)
						}
						m.Close()
					}
				}
				w.Flush()
			}
		}

		if showClosures {
			fmt.Println("Prog Closure Offsets")
			fmt.Println("====================")
			var pclosureAddr uint64
			if f.Headers[f.UUID].ProgClosuresTrieAddr != 0 {
				pclosureAddr = f.Headers[f.UUID].ProgClosuresAddr
			} else {
				pclosureAddr = f.Headers[f.UUID].ProgramsPblSetPoolAddr
			}
			pcs, err := f.GetProgClosuresOffsets()
			if err != nil {
				return err
			}
			for _, pc := range pcs {
				fmt.Printf("%#x\t%s\n", pclosureAddr+pc.Offset, string(pc.Data))
			}
		}

		if showDlopenOthers {
			fmt.Println("dlopen(s) Image/Bundle IDs")
			fmt.Println("==========================")
			oo, err := f.GetDlopenOtherImages()
			if err != nil {
				return err
			}
			for _, o := range oo {
				fmt.Printf("%4d: %s\n", o.Offset, string(o.Data))
			}
		}

		return nil
	},
}

func dyldInfoArgs(cmd *cobra.Command, args []string) error {
	diff := viper.GetBool("dyld.info.diff")
	delta := viper.GetBool("dyld.info.delta")
	if diff && delta {
		return errors.New("--diff and --delta are mutually exclusive")
	}
	if diff || delta {
		if !viper.GetBool("dyld.info.dylibs") {
			return errors.New("you must specify --dylibs to use --diff or --delta")
		}
		if len(args) != 2 {
			return fmt.Errorf("accepts 2 arg(s) when using --diff or --delta, received %d", len(args))
		}
		return nil
	}
	return cobra.ExactArgs(1)(cmd, args)
}

type dylibVersion struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type dylibVersionChange struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

type dylibComparison struct {
	Added   []dylibVersion       `json:"added"`
	Removed []dylibVersion       `json:"removed"`
	Changed []dylibVersionChange `json:"changed"`
}

func dylibVersions(f *dyld.File) (map[string]string, error) {
	versions := make(map[string]string, len(f.Images))
	for _, img := range f.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			return nil, fmt.Errorf("failed to create partial MachO for image %s: %w", img.Name, err)
		}
		version := ""
		if source := m.SourceVersion(); source != nil {
			version = source.Version.String()
		}
		versions[img.Name] = version
		m.Close()
	}
	return versions, nil
}

func compareDylibVersions(before, after map[string]string) dylibComparison {
	result := dylibComparison{
		Added: []dylibVersion{}, Removed: []dylibVersion{}, Changed: []dylibVersionChange{},
	}
	for name, oldVersion := range before {
		if newVersion, ok := after[name]; !ok {
			result.Removed = append(result.Removed, dylibVersion{Name: name, Version: oldVersion})
		} else if oldVersion != newVersion {
			result.Changed = append(result.Changed, dylibVersionChange{Name: name, OldVersion: oldVersion, NewVersion: newVersion})
		}
	}
	for name, version := range after {
		if _, ok := before[name]; !ok {
			result.Added = append(result.Added, dylibVersion{Name: name, Version: version})
		}
	}
	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].Name < result.Added[j].Name })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].Name < result.Removed[j].Name })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].Name < result.Changed[j].Name })
	return result
}
