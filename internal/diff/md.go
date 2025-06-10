package diff

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/apex/log"
	"golang.org/x/exp/rand"
)

// Markdown saves the diff as Markdown files.
func (d *Diff) Markdown() error {
	d.conf.Output = filepath.Join(d.conf.Output, d.TitleToFilename())
	if err := os.MkdirAll(d.conf.Output, 0o750); err != nil {
		return err
	}

	var out strings.Builder
	/* TOC */

	// SECTION: IPSWs
	out.WriteString(
		fmt.Sprintf(
			"# %s\n\n"+
				"## IPSWs\n\n"+
				"- `%s`\n"+
				"- `%s`\n\n",
			d.Title,
			filepath.Base(d.Old.IPSWPath),
			filepath.Base(d.New.IPSWPath),
		),
	)

	// SECTION: Kernel
	if d.Old.Kernel.Version != nil && d.New.Kernel.Version != nil {
		out.WriteString(
			fmt.Sprintf(
				"## Kernel\n\n"+
					"### Version\n\n"+
					"| iOS | Version | Build | Date |\n"+
					"| :-- | :------ | :---- | :--- |\n"+
					"| %s *(%s)* | %s | %s | %s |\n"+
					"| %s *(%s)* | %s | %s | %s |\n\n",
				d.Old.Version, d.Old.Build,
				d.Old.Kernel.Version.KernelVersion.Darwin, d.Old.Kernel.Version.KernelVersion.XNU,
				d.Old.Kernel.Version.KernelVersion.Date.Format("Mon, 02Jan2006 15:04:05 MST"),
				d.New.Version, d.New.Build,
				d.New.Kernel.Version.KernelVersion.Darwin, d.New.Kernel.Version.KernelVersion.XNU,
				d.New.Kernel.Version.KernelVersion.Date.Format("Mon, 02Jan2006 15:04:05 MST"),
			),
		)
	}

	// SUB-SECTION: Kexts
	if d.Kexts != nil && (len(d.Kexts.New) > 0 || len(d.Kexts.Removed) > 0 || len(d.Kexts.Updated) > 0) {
		out.WriteString("### Kexts\n\n")
		if len(d.Kexts.New) > 0 {
			out.WriteString(fmt.Sprintf("#### 🆕 NEW (%d)\n\n", len(d.Kexts.New)))
			slices.Sort(d.Kexts.New)
			for _, k := range d.Kexts.New {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			out.WriteString("\n")
		}
		if len(d.Kexts.Removed) > 0 {
			out.WriteString(fmt.Sprintf("#### ❌ Removed (%d)\n\n", len(d.Kexts.Removed)))
			slices.Sort(d.Kexts.Removed)
			for _, k := range d.Kexts.Removed {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			out.WriteString("\n")
		}

		if len(d.Kexts.Updated) > 0 {
			out.WriteString(fmt.Sprintf("### ⬆️ Updated (%d)\n\n", len(d.Kexts.Updated)))
			out.WriteString("<details>\n" +
				"  <summary><i>View Updated</i></summary>\n\n")

			keys := slices.Collect(maps.Keys(d.Kexts.Updated))
			slices.Sort(keys)

			if len(d.Kexts.Updated) < 10 {
				for _, k := range keys {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", d.Kexts.Updated[k]))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "KEXTS"), 0o750); err != nil {
					return err
				}
				for _, k := range keys {
					fname := filepath.Join(d.conf.Output, "KEXTS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")
					if _, err := os.Stat(fname); os.IsExist(err) {
						fname = filepath.Join(d.conf.Output, "KEXTS", fmt.Sprintf("%s.%d.md", strings.ReplaceAll(filepath.Base(k), " ", "_"), rand.Intn(20)))
					}
					log.Debugf("Creating diff kext Markdown file: %s", fname)
					f, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create diff file: %w", err)
					}
					fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
					fmt.Fprintf(f, "> `%s`\n\n", k)
					fmt.Fprintf(f, "%s", d.Kexts.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("KEXTS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	// SUB-SECTION: KDKs
	if len(d.KDKs) > 0 {
		out.WriteString("### KDKs\n\n")
		fname := filepath.Join(d.conf.Output, "KDK.md")
		log.Debugf("Creating diff KDK Markdown: %s", fname)
		f, err := os.Create(fname)
		if err != nil {
			return fmt.Errorf("failed to create diff KDK Markdown: %w", err)
		}
		fmt.Fprintf(f, "## KDKs\n\n"+
			"- `%s`\n"+
			"- `%s`\n\n",
			d.Old.KDK, d.New.KDK,
		)
		fmt.Fprintf(f, "%s", d.KDKs)
		out.WriteString(fmt.Sprintf("- [%s](%s)\n\n", "KDK DIFF", "KDK.md"))
	}

	// SECTION: MachO
	if d.Machos != nil && (len(d.Machos.New) > 0 || len(d.Machos.Removed) > 0 || len(d.Machos.Updated) > 0) {
		out.WriteString("## MachO\n\n")
		if len(d.Machos.New) > 0 {
			out.WriteString(fmt.Sprintf("### 🆕 NEW (%d)\n\n", len(d.Machos.New)))
			slices.Sort(d.Machos.New)
			if len(d.Machos.New) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View NEW</i></summary>\n\n")
			}
			for _, k := range d.Machos.New {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Machos.New) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Machos.Removed) > 0 {
			out.WriteString(fmt.Sprintf("### ❌ Removed (%d)\n\n", len(d.Machos.Removed)))
			slices.Sort(d.Machos.Removed)
			if len(d.Machos.Removed) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View Removed</i></summary>\n\n")
			}
			for _, k := range d.Machos.Removed {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Machos.Removed) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Machos.Updated) > 0 {
			out.WriteString(fmt.Sprintf("### ⬆️ Updated (%d)\n\n", len(d.Machos.Updated)))
			out.WriteString("<details>\n" +
				"  <summary><i>View Updated</i></summary>\n\n")

			keys := slices.Collect(maps.Keys(d.Machos.Updated))
			slices.Sort(keys)

			if len(d.Machos.Updated) < 20 {
				for _, k := range keys {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", d.Machos.Updated[k]))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "MACHOS"), 0o750); err != nil {
					return err
				}
				for _, k := range keys {
					fname := filepath.Join(d.conf.Output, "MACHOS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")
					if _, err := os.Stat(fname); os.IsExist(err) {
						fname = filepath.Join(d.conf.Output, "MACHOS", fmt.Sprintf("%s.%d.md", strings.ReplaceAll(filepath.Base(k), " ", "_"), rand.Intn(20)))
					}
					log.Debugf("Creating diff macho Markdown file: %s", fname)
					f, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create diff file: %w", err)
					}
					fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
					fmt.Fprintf(f, "> `%s`\n\n", k)
					fmt.Fprintf(f, "%s", d.Machos.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("MACHOS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	// SUB-SECTION: Entitlements
	if len(d.Ents) > 0 && d.Ents != "- No differences found\n" {
		out.WriteString("### 🔑 Entitlements\n\n")
		fname := filepath.Join(d.conf.Output, "Entitlements.md")
		log.Debugf("Creating diff Entitlements Markdown: %s", fname)
		f, err := os.Create(fname)
		if err != nil {
			return fmt.Errorf("failed to create diff Entitlements Markdown: %w", err)
		}
		fmt.Fprintf(f, "## 🔑 Entitlements\n\n")
		fmt.Fprintf(f, "%s", d.Ents)
		out.WriteString(fmt.Sprintf("- [%s](%s)\n\n", "Entitlements DIFF", "Entitlements.md"))
	}

	// SECTION: Firmware
	if d.Firmwares != nil && (len(d.Firmwares.New) > 0 || len(d.Firmwares.Removed) > 0 || len(d.Firmwares.Updated) > 0) {
		out.WriteString("## Firmware\n\n")
		if len(d.Firmwares.New) > 0 {
			out.WriteString(fmt.Sprintf("### 🆕 NEW (%d)\n\n", len(d.Firmwares.New)))
			slices.Sort(d.Firmwares.New)
			if len(d.Firmwares.New) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View NEW</i></summary>\n\n")
			}
			for _, k := range d.Firmwares.New {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Firmwares.New) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Firmwares.Removed) > 0 {
			out.WriteString(fmt.Sprintf("### ❌ Removed (%d)\n\n", len(d.Firmwares.Removed)))
			slices.Sort(d.Firmwares.Removed)
			if len(d.Firmwares.Removed) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View Removed</i></summary>\n\n")
			}
			for _, k := range d.Firmwares.Removed {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Firmwares.Removed) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Firmwares.Updated) > 0 {
			out.WriteString(fmt.Sprintf("### ⬆️ Updated (%d)\n\n", len(d.Firmwares.Updated)))
			out.WriteString("<details>\n" +
				"  <summary><i>View Updated</i></summary>\n\n")

			keys := slices.Collect(maps.Keys(d.Firmwares.Updated))
			slices.Sort(keys)

			if len(d.Firmwares.Updated) < 10 {
				for _, k := range keys {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", d.Firmwares.Updated[k]))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "FIRMWARE"), 0o750); err != nil {
					return err
				}
				for _, k := range keys {
					fname := filepath.Join(d.conf.Output, "FIRMWARE", filepath.Base(k)+".md")
					if _, err := os.Stat(fname); os.IsExist(err) {
						fname = filepath.Join(d.conf.Output, "FIRMWARE", fmt.Sprintf("%s.%d.md", filepath.Base(k), rand.Intn(20)))
					}
					log.Debugf("Creating diff firmware Markdown file: %s", fname)
					f, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create diff file: %w", err)
					}
					fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
					fmt.Fprintf(f, "> `%s`\n\n", k)
					fmt.Fprintf(f, "%s", d.Firmwares.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("FIRMWARE", filepath.Base(k)+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	// SECTION: iBoot
	if d.IBoot != nil {
		if len(d.IBoot.Versions) >= 2 {
			out.WriteString(
				fmt.Sprintf(
					"### iBoot\n\n"+
						"| iOS | Version |\n"+
						"| :-- | :------ |\n"+
						"| %s *(%s)* | %s |\n"+
						"| %s *(%s)* | %s |\n\n",
					d.Old.Version, d.Old.Build, d.IBoot.Versions[0],
					d.New.Version, d.New.Build, d.IBoot.Versions[1],
				),
			)
		}
		if len(d.IBoot.New) > 0 {
			out.WriteString(fmt.Sprintf("#### 🆕 NEW (%d)\n\n", len(d.IBoot.New)))
			out.WriteString("<details>\n" +
				"  <summary><i>View NEW</i></summary>\n\n")
			for k, v := range d.IBoot.New {
				out.WriteString(fmt.Sprintf("##### `%s`\n", k))
				for _, str := range v {
					out.WriteString(fmt.Sprintf("  - `%s`\n", str))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
		if len(d.IBoot.Removed) > 0 {
			out.WriteString(fmt.Sprintf("#### ❌ Removed (%d)\n\n", len(d.IBoot.Removed)))
			out.WriteString("<details>\n" +
				"  <summary><i>View Removed</i></summary>\n\n")
			for k, v := range d.IBoot.Removed {
				out.WriteString(fmt.Sprintf("##### `%s`\n", k))
				for _, str := range v {
					out.WriteString(fmt.Sprintf("  - `%s`\n", str))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	// SECTION: Launchd
	if len(d.Launchd) > 0 {
		out.WriteString("### launchd Config\n\n<details>\n  <summary><i>View Updated</i></summary>\n\n" + d.Launchd + "\n\n</details>\n\n")
	}

	// SECTION: DSC
	if d.Dylibs != nil {
		if (len(d.Old.Webkit) > 0 && len(d.New.Webkit) > 0) ||
			(d.Dylibs.New != nil || d.Dylibs.Removed != nil || d.Dylibs.Updated != nil) {
			out.WriteString("## DSC\n\n")
		}
	}
	if len(d.Old.Webkit) > 0 && len(d.New.Webkit) > 0 {
		out.WriteString(
			fmt.Sprintf(
				"### WebKit\n\n"+
					"| iOS | Version |\n"+
					"| :-- | :------ |\n"+
					"| %s *(%s)* | %s |\n"+
					"| %s *(%s)* | %s |\n\n",
				d.Old.Version, d.Old.Build, d.Old.Webkit,
				d.New.Version, d.New.Build, d.New.Webkit,
			),
		)
	}

	// SUB-SECTION: Dylibs
	if d.Dylibs != nil && (len(d.Dylibs.New) > 0 || len(d.Dylibs.Removed) > 0 || len(d.Dylibs.Updated) > 0) {
		out.WriteString("### Dylibs\n\n")
		if len(d.Dylibs.New) > 0 {
			out.WriteString(fmt.Sprintf("#### 🆕 NEW (%d)\n\n", len(d.Dylibs.New)))
			slices.Sort(d.Dylibs.New)
			if len(d.Dylibs.New) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View NEW</i></summary>\n\n")
			}
			for _, k := range d.Dylibs.New {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Dylibs.New) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Dylibs.Removed) > 0 {
			out.WriteString(fmt.Sprintf("#### ❌ Removed (%d)\n\n", len(d.Dylibs.Removed)))
			slices.Sort(d.Dylibs.Removed)
			if len(d.Dylibs.Removed) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View Removed</i></summary>\n\n")
			}
			for _, k := range d.Dylibs.Removed {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Dylibs.Removed) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Dylibs.Updated) > 0 {
			out.WriteString(fmt.Sprintf("#### ⬆️ Updated (%d)\n\n", len(d.Dylibs.Updated)))
			out.WriteString("<details>\n" +
				"  <summary><i>View Updated</i></summary>\n\n")

			keys := slices.Collect(maps.Keys(d.Dylibs.Updated))
			slices.Sort(keys)

			if len(d.Dylibs.Updated) < 20 {
				for _, k := range keys {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", d.Dylibs.Updated[k]))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "DYLIBS"), 0o750); err != nil {
					return err
				}
				for _, k := range keys {
					fname := filepath.Join(d.conf.Output, "DYLIBS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")
					if _, err := os.Stat(fname); os.IsExist(err) {
						fname = filepath.Join(d.conf.Output, "DYLIBS", fmt.Sprintf("%s.%d.md", strings.ReplaceAll(filepath.Base(k), " ", "_"), rand.Intn(20)))
					}
					log.Debugf("Creating diff dylib Markdown file: %s", fname)
					f, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create diff file: %w", err)
					}
					fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
					fmt.Fprintf(f, "> `%s`\n\n", k)
					fmt.Fprintf(f, "%s", d.Dylibs.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("DYLIBS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	// SUB-SECTION: Feature Flags
	if d.Files != nil {
		types := []string{"IPSW", "filesystem", "SystemOS", "AppOS", "ExclaveOS"}
		hasNewFiles := false
		hasRemovedFiles := false
		for _, t := range types {
			if len(d.Files.New[t]) > 0 {
				hasNewFiles = true
			}
			if len(d.Files.Removed[t]) > 0 {
				hasRemovedFiles = true
			}
		}
		if hasNewFiles || hasRemovedFiles {
			out.WriteString("## Files\n\n")
		}
		if hasNewFiles {
			if len(d.Files.New) > 0 {
				out.WriteString("### 🆕 New\n\n")
				for _, t := range types {
					if len(d.Files.New[t]) > 0 {
						out.WriteString(fmt.Sprintf("#### %s (%d)\n\n", t, len(d.Files.New[t])))
						if len(d.Files.New[t]) > 10 {
							out.WriteString("<details>\n" +
								"  <summary><i>View Files</i></summary>\n\n")
						}
						for _, k := range d.Files.New[t] {
							out.WriteString(fmt.Sprintf("- `%s`\n", k))
						}
						if len(d.Files.New[t]) > 10 {
							out.WriteString("\n</details>\n")
						}
						out.WriteString("\n")
					}
				}
			}
		}
		if hasRemovedFiles {
			out.WriteString("### ❌ Removed\n\n")
			for _, t := range types {
				if len(d.Files.Removed[t]) > 0 {
					out.WriteString(fmt.Sprintf("#### %s (%d)\n\n", t, len(d.Files.Removed[t])))
					if len(d.Files.Removed[t]) > 10 {
						out.WriteString("<details>\n" +
							"  <summary><i>View Files</i></summary>\n\n")
					}
					for _, k := range d.Files.Removed[t] {
						out.WriteString(fmt.Sprintf("- `%s`\n", k))
					}
					if len(d.Files.Removed[t]) > 10 {
						out.WriteString("\n</details>\n")
					}
					out.WriteString("\n")
				}
			}
		}
	}

	// SUB-SECTION: Feature Flags
	if d.Features != nil && (len(d.Features.New) > 0 || len(d.Features.Removed) > 0 || len(d.Features.Updated) > 0) {
		out.WriteString("## Feature Flags\n\n")
		if len(d.Features.New) > 0 {
			out.WriteString(fmt.Sprintf("### 🆕 NEW (%d)\n\n", len(d.Features.New)))
			out.WriteString("<details>\n" +
				"  <summary><i>View New</i></summary>\n\n")
			if len(d.Features.New) < 20 {
				for k, v := range d.Features.New {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("```xml\n%s\n```\n", v))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "FEATURES"), 0o750); err != nil {
					return err
				}
				keys := make([]string, 0, len(d.Features.New))
				for k := range d.Features.New {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					fname := filepath.Join(d.conf.Output, "FEATURES", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")
					if _, err := os.Stat(fname); os.IsExist(err) {
						fname = filepath.Join(d.conf.Output, "FEATURES", fmt.Sprintf("%s.%d.md", strings.ReplaceAll(filepath.Base(k), " ", "_"), rand.Intn(20)))
					}
					log.Debugf("Creating diff feature Markdown file: %s", fname)
					f, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create diff file: %w", err)
					}
					fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
					fmt.Fprintf(f, "> `%s`\n\n", k)
					fmt.Fprintf(f, d.Features.New[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("FEATURES", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
		if len(d.Features.Removed) > 0 {
			out.WriteString(fmt.Sprintf("### ❌ Removed (%d)\n\n", len(d.Features.Removed)))
			if len(d.Features.Removed) > 30 {
				out.WriteString("<details>\n" +
					"  <summary><i>View Removed</i></summary>\n\n")
			}
			for _, k := range d.Features.Removed {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			if len(d.Features.Removed) > 30 {
				out.WriteString("\n</details>\n")
			}
			out.WriteString("\n")
		}
		if len(d.Features.Updated) > 0 {
			out.WriteString(fmt.Sprintf("### ⬆️ Updated (%d)\n\n", len(d.Features.Updated)))
			out.WriteString("<details>\n" +
				"  <summary><i>View Updated</i></summary>\n\n")

			keys := slices.Collect(maps.Keys(d.Features.Updated))
			slices.Sort(keys)

			if len(d.Features.Updated) < 15 {
				for _, k := range keys {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", d.Features.Updated[k]))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "FEATURES"), 0o750); err != nil {
					return err
				}
				for _, k := range keys {
					fname := filepath.Join(d.conf.Output, "FEATURES", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")
					if _, err := os.Stat(fname); os.IsExist(err) {
						fname = filepath.Join(d.conf.Output, "FEATURES", fmt.Sprintf("%s.%d.md", strings.ReplaceAll(filepath.Base(k), " ", "_"), rand.Intn(20)))
					}
					log.Debugf("Creating diff feature Markdown file: %s", fname)
					f, err := os.Create(fname)
					if err != nil {
						return fmt.Errorf("failed to create diff file: %w", err)
					}
					fmt.Fprintf(f, "## %s\n\n", filepath.Base(k))
					fmt.Fprintf(f, "> `%s`\n\n", k)
					fmt.Fprintf(f, "%s", d.Features.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("FEATURES", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	out.WriteString("## EOF\n")

	// Write README.md
	if err := os.MkdirAll(d.conf.Output, 0o750); err != nil {
		return err
	}
	fname := filepath.Join(d.conf.Output, "README.md")
	log.Infof("Creating diff file Markdown README: %s", fname)
	return os.WriteFile(fname, []byte(out.String()), 0o644)
}
