// Package macho provides functionality for parsing Mach-O files.
package macho

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"text/template"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types/objc"
	"github.com/blacktop/ipsw/internal/swift"
)

// ErrNoObjc is returned when a MachO does not contain objc info
var ErrNoObjc = errors.New("macho does not contain objc info")

// Config for MachO ObjC parser
type Config struct {
	Name     string
	Verbose  bool
	Addrs    bool
	ObjcRefs bool
	Demangle bool

	IpswVersion   string
	BuildVersions []string
	SourceVersion string

	Color  bool
	Theme  string
	Output string
}

// DumpClass returns a ObjC classes matching a given pattern from a MachO
func DumpClass(m *macho.File, pattern string, conf *Config) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}

	classes, err := m.GetObjCClasses()
	if err != nil {
		if errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		return err
	}

	slices.SortStableFunc(classes, func(a, b objc.Class) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, class := range classes {
		if re.MatchString(class.Name) {
			if conf.Color {
				if conf.Addrs {
					quick.Highlight(os.Stdout, swift.DemangleBlob(class.WithAddrs()), "objc", "terminal256", conf.Theme)
				} else {
					quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", conf.Theme)
				}
				quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
			} else {
				if conf.Addrs {
					fmt.Println(swift.DemangleBlob(class.WithAddrs()))
				} else {
					fmt.Println(swift.DemangleBlob(class.Verbose()))
				}
			}
		}
	}

	return nil
}

// DumpProtocol returns a ObjC protocols matching a given pattern from a MachO
func DumpProtocol(m *macho.File, pattern string, conf *Config) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}

	protos, err := m.GetObjCProtocols()
	if err != nil {
		if errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		return err
	}

	slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
		return cmp.Compare(a.Name, b.Name)
	})
	seen := make(map[uint64]bool)

	for _, proto := range protos {
		if re.MatchString(proto.Name) {
			if conf.Color {
				if conf.Addrs {
					quick.Highlight(os.Stdout, swift.DemangleBlob(proto.WithAddrs()), "objc", "terminal256", conf.Theme)
				} else {
					quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", conf.Theme)
				}
				quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
			} else {
				if conf.Addrs {
					fmt.Println(swift.DemangleBlob(proto.WithAddrs()))
				} else {
					fmt.Println(swift.DemangleBlob(proto.Verbose()))
				}
			}
			seen[proto.Ptr] = true
		}
	}

	return nil
}

// DumpCategory returns a ObjC categories matching a given pattern from a MachO
func DumpCategory(m *macho.File, pattern string, conf *Config) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}

	cats, err := m.GetObjCCategories()
	if err != nil {
		if errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		return err
	}

	slices.SortStableFunc(cats, func(a, b objc.Category) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, cat := range cats {
		if re.MatchString(cat.Name) {
			if conf.Color {
				if conf.Addrs {
					quick.Highlight(os.Stdout, swift.DemangleBlob(cat.WithAddrs()), "objc", "terminal256", conf.Theme)
				} else {
					quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", conf.Theme)
				}
				quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
			} else {
				if conf.Addrs {
					fmt.Println(swift.DemangleBlob(cat.WithAddrs()))
				} else {
					fmt.Println(swift.DemangleBlob(cat.Verbose()))
				}
			}
		}
	}

	return nil
}

// Dump outputs ObjC info from a MachO
func Dump(m *macho.File, conf *Config) error {
	if info, err := m.GetObjCImageInfo(); err == nil {
		fmt.Println(info.Flags)
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return err
	}
	if conf.Verbose {
		fmt.Println(m.GetObjCToc())
	}
	/* ObjC Protocols */
	if protos, err := m.GetObjCProtocols(); err == nil {
		slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
			return cmp.Compare(a.Name, b.Name)
		})
		seen := make(map[uint64]bool)
		for _, proto := range protos {
			if _, ok := seen[proto.Ptr]; !ok { // prevent displaying duplicates
				if conf.Verbose {
					if conf.Color {
						if conf.Addrs {
							quick.Highlight(os.Stdout, swift.DemangleBlob(proto.WithAddrs()), "objc", "terminal256", conf.Theme)
						} else {
							quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", conf.Theme)
						}
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
					} else {
						if conf.Addrs {
							fmt.Println(swift.DemangleBlob(proto.WithAddrs()))
						} else {
							fmt.Println(swift.DemangleBlob(proto.Verbose()))
						}
					}
				} else {
					if conf.Color {
						quick.Highlight(os.Stdout, proto.String()+"\n", "objc", "terminal256", conf.Theme)
					} else {
						fmt.Println(proto.String())
					}
				}
				seen[proto.Ptr] = true
			}
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return err
	}
	/* ObjC Classes */
	if classes, err := m.GetObjCClasses(); err == nil {
		slices.SortStableFunc(classes, func(a, b objc.Class) int {
			return cmp.Compare(a.Name, b.Name)
		})
		for _, class := range classes {
			if conf.Verbose {
				if conf.Color {
					if conf.Addrs {
						quick.Highlight(os.Stdout, swift.DemangleBlob(class.WithAddrs()), "objc", "terminal256", conf.Theme)
					} else {
						quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", conf.Theme)
					}
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
				} else {
					if conf.Addrs {
						fmt.Println(swift.DemangleBlob(class.WithAddrs()))
					} else {
						fmt.Println(swift.DemangleBlob(class.Verbose()))
					}
				}
			} else {
				if conf.Color {
					quick.Highlight(os.Stdout, class.String()+"\n", "objc", "terminal256", conf.Theme)
				} else {
					fmt.Println(class.String())
				}
			}
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return err
	}
	/* ObjC Categories */
	if cats, err := m.GetObjCCategories(); err == nil {
		slices.SortStableFunc(cats, func(a, b objc.Category) int {
			return cmp.Compare(a.Name, b.Name)
		})
		for _, cat := range cats {
			if conf.Verbose {
				if conf.Color {
					if conf.Addrs {
						quick.Highlight(os.Stdout, swift.DemangleBlob(cat.WithAddrs()), "objc", "terminal256", conf.Theme)
					} else {
						quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", conf.Theme)
					}
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
				} else {
					if conf.Addrs {
						fmt.Println(swift.DemangleBlob(cat.WithAddrs()))
					} else {
						fmt.Println(swift.DemangleBlob(cat.Verbose()))
					}
				}
			} else {
				if conf.Color {
					quick.Highlight(os.Stdout, cat.String()+"\n", "objc", "terminal256", conf.Theme)
				} else {
					fmt.Println(cat.String())
				}
			}
		}
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		return err
	}
	if conf.ObjcRefs {
		if protRefs, err := m.GetObjCProtoReferences(); err == nil {
			fmt.Printf("\n@protocol refs\n")
			for off, prot := range protRefs {
				fmt.Printf("0x%011x => 0x%011x: %s\n", off, prot.Ptr, prot.Name)
			}
		} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		if clsRefs, err := m.GetObjCClassReferences(); err == nil {
			fmt.Printf("\n@class refs\n")
			for off, cls := range clsRefs {
				fmt.Printf("0x%011x => 0x%011x: %s\n", off, cls.ClassPtr, cls.Name)
			}
		} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		if supRefs, err := m.GetObjCSuperReferences(); err == nil {
			fmt.Printf("\n@super refs\n")
			for off, sup := range supRefs {
				fmt.Printf("0x%011x => 0x%011x: %s\n", off, sup.ClassPtr, sup.Name)
			}
		} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		if selRefs, err := m.GetObjCSelectorReferences(); err == nil {
			fmt.Printf("\n@selectors refs\n")
			for off, sel := range selRefs {
				fmt.Printf("0x%011x => 0x%011x: %s\n", off, sel.VMAddr, sel.Name)
			}
		} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		if conf.Verbose {
			if classes, err := m.GetObjCClassNames(); err == nil {
				fmt.Printf("\n@objc_classname\n")
				for vmaddr, className := range classes {
					fmt.Printf("0x%011x: %s\n", vmaddr, className)
				}
			} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				return err
			}
			if methods, err := m.GetObjCMethodNames(); err == nil {
				fmt.Printf("\n@objc_methname\n")
				for vmaddr, method := range methods {
					fmt.Printf("0x%011x: %s\n", vmaddr, method)
				}
			} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				return err
			}
		}
	}

	return nil
}

func transformSetter(in string) string {
	if strings.HasPrefix(in, "set") {
		in = strings.TrimSuffix(strings.TrimPrefix(in, "set"), ":")
		if len(in) > 0 {
			return strings.ToLower(in[:1]) + in[1:]
		}
		return ""
	}
	return in
}

const classDumpHeader = `
//
//   Generated by https://github.com/blacktop/ipsw ({{ .IpswVersion }})
//
{{- range .BuildVersions }}
//    - LC_BUILD_VERSION:  {{.}}
{{ end -}}
//    - LC_SOURCE_VERSION: {{ .SourceVersion }}
//
#ifndef {{ .Name }}_h
#define {{ .Name }}_h
{{ if not .IsUmbrella }}{{ "@import Foundation;" | println }}{{- end }}
{{ .Object }}
#endif /* {{ .Name }}_h */
`

// Headers outputs ObjC class-dump headers from a MachO
func Headers(m *macho.File, conf *Config) error {
	if !m.HasObjC() {
		return ErrNoObjc
	}

	var headers []string

	/* generate ObjC class headers */
	classes, err := m.GetObjCClasses()
	if err != nil {
		if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
	}
	slices.SortStableFunc(classes, func(a, b objc.Class) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, class := range classes {
		var props []string
		for _, prop := range class.Props {
			props = append(props, prop.Name)
		}
		sort.Strings(props)
		// remove ivars that are properties
		class.Ivars = slices.DeleteFunc(class.Ivars, func(i objc.Ivar) bool {
			// return slices.Contains(props, i.Name) || slices.Contains(props, strings.TrimPrefix(i.Name, "_")) TODO: use this instead
			return slices.Contains(props, strings.TrimPrefix(i.Name, "_"))
		})
		// remove methods that are property getter/setter
		class.InstanceMethods = slices.DeleteFunc(class.InstanceMethods, func(m objc.Method) bool {
			return slices.Contains(props, m.Name) || slices.Contains(props, transformSetter(m.Name))
		})

		var headerDat bytes.Buffer
		tmpl := template.Must(template.New("header").Parse(classDumpHeader))

		if err := tmpl.Execute(&headerDat, struct {
			IpswVersion   string
			BuildVersions []string
			SourceVersion string
			IsUmbrella    bool
			Name          string
			Object        string
		}{
			IpswVersion:   conf.IpswVersion,
			BuildVersions: conf.BuildVersions,
			SourceVersion: conf.SourceVersion,
			Name:          class.Name,
			Object:        swift.DemangleBlob(class.Verbose()),
		}); err != nil {
			return fmt.Errorf("failed to generate header for %s: %v", class.Name, err)
		}

		fname := filepath.Join(conf.Output, class.Name+".h")
		log.Infof("Creating %s", fname)
		if err := os.WriteFile(fname, headerDat.Bytes(), 0644); err != nil {
			return fmt.Errorf("failed to write header for %s: %v", class.Name, err)
		}
		headers = append(headers, class.Name+".h")
	}

	/* generate ObjC protocol headers */
	protos, err := m.GetObjCProtocols()
	if err != nil {
		return err
	}
	slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
		return cmp.Compare(a.Name, b.Name)
	})
	seen := make(map[uint64]bool)
	for _, proto := range protos {
		if _, ok := seen[proto.Ptr]; !ok { // prevent displaying duplicates
			var headerDat bytes.Buffer
			tmpl := template.Must(template.New("header").Parse(classDumpHeader))

			if err := tmpl.Execute(&headerDat, struct {
				IpswVersion   string
				BuildVersions []string
				SourceVersion string
				IsUmbrella    bool
				Name          string
				Object        string
			}{
				IpswVersion:   conf.IpswVersion,
				BuildVersions: conf.BuildVersions,
				SourceVersion: conf.SourceVersion,
				Name:          proto.Name,
				Object:        swift.DemangleBlob(proto.Verbose()),
			}); err != nil {
				return fmt.Errorf("failed to generate header for %s: %v", proto.Name, err)
			}

			fname := filepath.Join(conf.Output, proto.Name+"-Protocol.h")
			log.Infof("Creating %s", fname)
			if err := os.WriteFile(fname, headerDat.Bytes(), 0644); err != nil {
				return fmt.Errorf("failed to write header for %s: %v", proto.Name, err)
			}
			headers = append(headers, proto.Name+"-Protocol.h")
			seen[proto.Ptr] = true
		}
	}

	/* generate ObjC category headers */
	cats, err := m.GetObjCCategories()
	if err != nil {
		return err
	}
	slices.SortStableFunc(cats, func(a, b objc.Category) int {
		return cmp.Compare(a.Name, b.Name)
	})
	// FIXME: when running on `apsd` there is 4 (apsd) categories ?? these overwrite each other
	for _, cat := range cats {
		var headerDat bytes.Buffer
		tmpl := template.Must(template.New("header").Parse(classDumpHeader))

		if err := tmpl.Execute(&headerDat, struct {
			IpswVersion   string
			BuildVersions []string
			SourceVersion string
			IsUmbrella    bool
			Name          string
			Object        string
		}{
			IpswVersion:   conf.IpswVersion,
			BuildVersions: conf.BuildVersions,
			SourceVersion: conf.SourceVersion,
			Name:          cat.Name,
			Object:        swift.DemangleBlob(cat.Verbose()),
		}); err != nil {
			return fmt.Errorf("failed to generate header for %s: %v", cat.Name, err)
		}

		fname := filepath.Join(conf.Output, cat.Name+".h")
		log.Infof("Creating %s", fname)
		if err := os.WriteFile(fname, headerDat.Bytes(), 0644); err != nil {
			return fmt.Errorf("failed to write header for %s: %v", cat.Name, err)
		}
		headers = append(headers, cat.Name+".h")
	}

	// generate umbrella header
	var umbrella string
	if slices.Contains(headers, conf.Name+".h") {
		umbrella = conf.Name + "-Umbrella"
	} else {
		umbrella = conf.Name
	}

	for i, header := range headers {
		headers[i] = "#import \"" + header + "\""
	}

	var headerDat bytes.Buffer
	tmpl := template.Must(template.New("header").Parse(classDumpHeader))

	if err := tmpl.Execute(&headerDat, struct {
		IpswVersion   string
		BuildVersions []string
		SourceVersion string
		IsUmbrella    bool
		Name          string
		Object        string
	}{
		IpswVersion:   conf.IpswVersion,
		BuildVersions: conf.BuildVersions,
		SourceVersion: conf.SourceVersion,
		IsUmbrella:    true,
		Name:          strings.ReplaceAll(umbrella, "-", "_"),
		Object:        strings.Join(headers, "\n") + "\n",
	}); err != nil {
		return fmt.Errorf("failed to generate header for %s: %v", umbrella, err)
	}

	fname := filepath.Join(conf.Output, umbrella+".h")
	log.Infof("Creating %s", fname)
	if err := os.WriteFile(fname, headerDat.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write header for %s: %v", umbrella, err)
	}

	return nil
}
