package diff

import (
	"fmt"
	"os"
	"path/filepath"
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

	// SUB-SECTION: Kexts
	if d.Kexts != nil && (len(d.Kexts.New) > 0 || len(d.Kexts.Removed) > 0 || len(d.Kexts.Updated) > 0) {
		out.WriteString("### Kexts\n\n")
		if len(d.Kexts.New) > 0 {
			out.WriteString(fmt.Sprintf("#### 🆕 NEW (%d)\n\n", len(d.Kexts.New)))
			for _, k := range d.Kexts.New {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			out.WriteString("\n")
		}
		if len(d.Kexts.Removed) > 0 {
			out.WriteString(fmt.Sprintf("#### ❌ Removed (%d)\n\n", len(d.Kexts.Removed)))
			for _, k := range d.Kexts.Removed {
				out.WriteString(fmt.Sprintf("- `%s`\n", k))
			}
			out.WriteString("\n")
		}
		if len(d.Kexts.Updated) > 0 {
			out.WriteString(
				fmt.Sprintf(
					"#### ⬆️ Updated (%d)\n\n"+
						"<details>\n"+
						"  <summary><i>View Updated</i></summary>\n\n",
					len(d.Kexts.Updated)))

			for k, v := range d.Kexts.Updated {
				out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
				out.WriteString(fmt.Sprintf("%s\n", v))
			}
			out.WriteString("</details>\n\n")
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
		fmt.Fprintf(f, d.KDKs)
		out.WriteString(fmt.Sprintf("- [%s](%s)\n\n", "KDK DIFF", "KDK.md"))
	}

	// SECTION: MachO
	if d.Machos != nil && (len(d.Machos.New) > 0 || len(d.Machos.Removed) > 0 || len(d.Machos.Updated) > 0) {
		out.WriteString("## MachO\n\n")
		if len(d.Machos.New) > 0 {
			out.WriteString(fmt.Sprintf("### 🆕 NEW (%d)\n\n", len(d.Machos.New)))
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
			if len(d.Machos.Updated) < 20 {
				for k, v := range d.Machos.Updated {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", v))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "MACHOS"), 0o750); err != nil {
					return err
				}
				keys := make([]string, 0, len(d.Machos.Updated))
				for k := range d.Machos.Updated {
					keys = append(keys, k)
				}
				sort.Strings(keys)
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
					fmt.Fprintf(f, d.Machos.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("MACHOS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	// SUB-SECTION: Entitlements
	if len(d.Ents) > 0 {
		out.WriteString("### 🔑 Entitlements\n\n")
		fname := filepath.Join(d.conf.Output, "Entitlements.md")
		log.Debugf("Creating diff Entitlements Markdown: %s", fname)
		f, err := os.Create(fname)
		if err != nil {
			return fmt.Errorf("failed to create diff Entitlements Markdown: %w", err)
		}
		fmt.Fprintf(f, "## 🔑 Entitlements\n\n")
		fmt.Fprintf(f, d.Ents)
		out.WriteString(fmt.Sprintf("- [%s](%s)\n\n", "Entitlements DIFF", "Entitlements.md"))
	}

	// SECTION: Firmware
	if d.Firmwares != nil && (len(d.Firmwares.New) > 0 || len(d.Firmwares.Removed) > 0 || len(d.Firmwares.Updated) > 0) {
		out.WriteString("## Firmware\n\n")
		if len(d.Firmwares.New) > 0 {
			out.WriteString(fmt.Sprintf("### 🆕 NEW (%d)\n\n", len(d.Firmwares.New)))
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
			keys := make([]string, 0, len(d.Firmwares.Updated))
			for k := range d.Firmwares.Updated {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if len(d.Firmwares.Updated) < 20 {
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
					fmt.Fprintf(f, d.Firmwares.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("FIRMWARE", filepath.Base(k)+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	// SECTION: Launchd
	if len(d.Launchd) > 0 {
		out.WriteString("### Launchd\n\n" + d.Launchd + "\n")
	}

	// SECTION: DSC
	out.WriteString("## DSC\n\n")
	if len(d.Old.Webkit) > 0 {
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
			if len(d.Dylibs.Updated) < 20 {
				for k, v := range d.Dylibs.Updated {
					out.WriteString(fmt.Sprintf("#### %s\n\n", filepath.Base(k)))
					out.WriteString(fmt.Sprintf(">  `%s`\n\n", k))
					out.WriteString(fmt.Sprintf("%s\n", v))
				}
			} else {
				if err := os.MkdirAll(filepath.Join(d.conf.Output, "DYLIBS"), 0o750); err != nil {
					return err
				}
				keys := make([]string, 0, len(d.Dylibs.Updated))
				for k := range d.Dylibs.Updated {
					keys = append(keys, k)
				}
				sort.Strings(keys)
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
					fmt.Fprintf(f, d.Dylibs.Updated[k])
					f.Close()
					out.WriteString(fmt.Sprintf("- [%s](%s)\n", k, filepath.Join("DYLIBS", strings.ReplaceAll(filepath.Base(k), " ", "_")+".md")))
				}
			}
			out.WriteString("\n</details>\n\n")
		}
	}

	out.WriteString("## EOF\n")

	// Write TOC.md
	if err := os.MkdirAll(d.conf.Output, 0o750); err != nil {
		return err
	}
	fname := filepath.Join(d.conf.Output, "TOC.md")
	log.Infof("Creating diff file Markdown TOC: %s", fname)
	return os.WriteFile(fname, []byte(out.String()), 0o644)
}
