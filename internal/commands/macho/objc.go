// Package macho provides functionality for parsing Mach-O files.
package macho

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-macho/types/objc"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/tbd"
)

// ErrNoObjc is returned when a MachO does not contain objc info
var ErrNoObjc = errors.New("macho does not contain objc info")

var baseFrameworks = []string{"Foundation", "CoreFoundation", "libobjc.A.dylib"}

// ObjcConfig for MachO ObjC parser
type ObjcConfig struct {
	Name     string
	Verbose  bool
	Addrs    bool
	Headers  bool
	ObjcRefs bool
	Deps     bool
	Generic  bool

	IpswVersion string

	Color  bool
	Theme  string
	Output string
}

// Imports represents the imported symbols, local symbols, classes, and protocols for a ObjC header
type Imports struct {
	Imports []string
	Locals  []string
	Classes []string
	Protos  []string
}

func (i *Imports) uniq(foundation map[string][]string) {
	slices.Sort(i.Imports)
	slices.Sort(i.Locals)
	slices.Sort(i.Classes)
	slices.Sort(i.Protos)
	i.Imports = slices.Compact(i.Imports)
	i.Locals = slices.Compact(i.Locals)
	i.Classes = slices.Compact(i.Classes)
	i.Protos = slices.Compact(i.Protos)
	i.Imports = slices.DeleteFunc(i.Imports, func(l string) bool {
		l = strings.TrimSuffix(l, "-Protocol.h")
		l = strings.TrimSuffix(l, ".h")
		_, foundC := slices.BinarySearch(foundation["classes"], l)
		_, foundP := slices.BinarySearch(foundation["protocols"], l)
		return foundC || foundP
	})
	i.Locals = slices.DeleteFunc(i.Locals, func(l string) bool {
		l = strings.TrimSuffix(l, "-Protocol.h")
		l = strings.TrimSuffix(l, ".h")
		_, foundC := slices.BinarySearch(foundation["classes"], l)
		_, foundP := slices.BinarySearch(foundation["protocols"], l)
		return foundC || foundP
	})
	// remove Foundation classes
	i.Classes = slices.DeleteFunc(i.Classes, func(c string) bool {
		_, found := slices.BinarySearch(foundation["classes"], c)
		return found
	})
	// remove Foundation protocols
	i.Protos = slices.DeleteFunc(i.Protos, func(p string) bool {
		_, found := slices.BinarySearch(foundation["protocols"], p)
		return found
	})
}

type headerInfo struct {
	FileName      string
	IpswVersion   string
	BuildVersions []string
	SourceVersion string
	IsUmbrella    bool
	Name          string
	Imports       Imports
	Object        string
}

// ObjC represents a MachO ObjC parser
type ObjC struct {
	conf  *ObjcConfig
	file  *macho.File
	cache *dyld.File
	deps  []*macho.File

	baseFWs map[string][]string
}

// NewObjC returns a new MachO ObjC parser instance
func NewObjC(file *macho.File, dsc *dyld.File, conf *ObjcConfig) (*ObjC, error) {
	if !file.HasObjC() {
		return nil, ErrNoObjc
	}

	o := &ObjC{
		conf:    conf,
		file:    file,
		cache:   dsc,
		baseFWs: make(map[string][]string),
	}

	if o.conf.Deps {
		if dsc == nil {
			return nil, fmt.Errorf("dyld shared cache is required to dump imported private frameworks")
		}
		var deps []string
		for _, imp := range file.ImportedLibraries() {
			if o.conf.Headers {
				// only dump private frameworks when generating headers
				if strings.Contains(imp, "PrivateFrameworks") {
					deps = append(deps, imp)
				}
			} else {
				deps = append(deps, imp)
			}
		}
		for _, imageName := range deps {
			img, err := o.cache.Image(imageName)
			if err != nil {
				return nil, err
			}
			m, err := img.GetMacho()
			if err != nil {
				return nil, err
			}
			o.deps = append(o.deps, m)
		}
	}

	return o, nil
}

// DumpClass returns a ObjC classes matching a given pattern from a MachO
func (o *ObjC) DumpClass(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	ms := []*macho.File{o.file}
	if o.conf.Deps {
		ms = append(ms, o.deps...)
	}
	for _, m := range ms {
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
				if o.conf.Color {
					if o.conf.Addrs {
						quick.Highlight(os.Stdout, swift.DemangleBlob(class.WithAddrs()), "objc", "terminal256", o.conf.Theme)
					} else {
						quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", o.conf.Theme)
					}
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", o.conf.Theme)
				} else {
					if o.conf.Addrs {
						fmt.Println(swift.DemangleBlob(class.WithAddrs()))
					} else {
						fmt.Println(swift.DemangleBlob(class.Verbose()))
					}
				}
			}
		}
	}
	return nil
}

// DumpProtocol returns a ObjC protocols matching a given pattern from a MachO
func (o *ObjC) DumpProtocol(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	ms := []*macho.File{o.file}
	if o.conf.Deps {
		ms = append(ms, o.deps...)
	}
	for _, m := range ms {
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
				if _, ok := seen[proto.Ptr]; !ok { // prevent displaying duplicates
					if o.conf.Color {
						if o.conf.Addrs {
							quick.Highlight(os.Stdout, swift.DemangleBlob(proto.WithAddrs()), "objc", "terminal256", o.conf.Theme)
						} else {
							quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", o.conf.Theme)
						}
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", o.conf.Theme)
					} else {
						if o.conf.Addrs {
							fmt.Println(swift.DemangleBlob(proto.WithAddrs()))
						} else {
							fmt.Println(swift.DemangleBlob(proto.Verbose()))
						}
					}
					seen[proto.Ptr] = true
				}
			}
		}
	}
	return nil
}

// DumpCategory returns a ObjC categories matching a given pattern from a MachO
func (o *ObjC) DumpCategory(pattern string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("failed to compile regex: %v", err)
	}
	ms := []*macho.File{o.file}
	if o.conf.Deps {
		ms = append(ms, o.deps...)
	}
	for _, m := range ms {
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
				if o.conf.Color {
					if o.conf.Addrs {
						quick.Highlight(os.Stdout, swift.DemangleBlob(cat.WithAddrs()), "objc", "terminal256", o.conf.Theme)
					} else {
						quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", o.conf.Theme)
					}
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", o.conf.Theme)
				} else {
					if o.conf.Addrs {
						fmt.Println(swift.DemangleBlob(cat.WithAddrs()))
					} else {
						fmt.Println(swift.DemangleBlob(cat.Verbose()))
					}
				}
			}
		}
	}
	return nil
}

// Dump outputs ObjC info from a MachO
func (o *ObjC) Dump() error {
	ms := []*macho.File{o.file}
	if o.conf.Deps {
		ms = append(ms, o.deps...)
	}
	for _, m := range ms {
		if o.conf.Verbose {
			if info, err := m.GetObjCImageInfo(); err == nil {
				fmt.Println(info.Flags)
			} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				return err
			}
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
					if o.conf.Verbose {
						if o.conf.Color {
							if o.conf.Addrs {
								quick.Highlight(os.Stdout, swift.DemangleBlob(proto.WithAddrs()), "objc", "terminal256", o.conf.Theme)
							} else {
								quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", o.conf.Theme)
							}
							quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", o.conf.Theme)
						} else {
							if o.conf.Addrs {
								fmt.Println(swift.DemangleBlob(proto.WithAddrs()))
							} else {
								fmt.Println(swift.DemangleBlob(proto.Verbose()))
							}
						}
					} else {
						if o.conf.Color {
							quick.Highlight(os.Stdout, proto.String()+"\n", "objc", "terminal256", o.conf.Theme)
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
				if o.conf.Verbose {
					if o.conf.Color {
						if o.conf.Addrs {
							quick.Highlight(os.Stdout, swift.DemangleBlob(class.WithAddrs()), "objc", "terminal256", o.conf.Theme)
						} else {
							quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", o.conf.Theme)
						}
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", o.conf.Theme)
					} else {
						if o.conf.Addrs {
							fmt.Println(swift.DemangleBlob(class.WithAddrs()))
						} else {
							fmt.Println(swift.DemangleBlob(class.Verbose()))
						}
					}
				} else {
					if o.conf.Color {
						quick.Highlight(os.Stdout, class.String()+"\n", "objc", "terminal256", o.conf.Theme)
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
				if o.conf.Verbose {
					if o.conf.Color {
						if o.conf.Addrs {
							quick.Highlight(os.Stdout, swift.DemangleBlob(cat.WithAddrs()), "objc", "terminal256", o.conf.Theme)
						} else {
							quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", o.conf.Theme)
						}
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", o.conf.Theme)
					} else {
						if o.conf.Addrs {
							fmt.Println(swift.DemangleBlob(cat.WithAddrs()))
						} else {
							fmt.Println(swift.DemangleBlob(cat.Verbose()))
						}
					}
				} else {
					if o.conf.Color {
						quick.Highlight(os.Stdout, cat.String()+"\n", "objc", "terminal256", o.conf.Theme)
					} else {
						fmt.Println(cat.String())
					}
				}
			}
		} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return err
		}
		if o.conf.ObjcRefs {
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
			if o.conf.Verbose {
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
	}
	return nil
}

// Headers outputs ObjC class-dump headers from a MachO
func (o *ObjC) Headers() error {

	// scan DSC for Foundation/CoreFoundation classes and protocols
	if err := o.scanBaseFrameworks(); err != nil {
		return err
	}

	writeHeaders := func(m *macho.File) error {
		var headers []string

		if !m.HasObjC() {
			return nil
		}

		if id := m.DylibID(); id != nil {
			o.conf.Name = filepath.Base(id.Name)
		}
		var buildVersions []string
		if bvers := m.GetLoadsByName("LC_BUILD_VERSION"); len(bvers) > 0 {
			for _, bv := range bvers {
				buildVersions = append(buildVersions, bv.String())
			}
		}
		var sourceVersion string
		if svers := m.GetLoadsByName("LC_SOURCE_VERSION"); len(svers) > 0 {
			sourceVersion = svers[0].String()
		}

		imps, err := o.processForwardDeclarations(m)
		if err != nil {
			return err
		}

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
			var setters []string
			for _, prop := range class.Props {
				props = append(props, prop.Name)
				setters = append(setters, "set"+strings.ToUpper(prop.Name[:1])+prop.Name[1:]+":")
			}
			slices.Sort(props)
			slices.Sort(setters)
			// remove ivars that are properties
			class.Ivars = slices.DeleteFunc(class.Ivars, func(i objc.Ivar) bool {
				// return slices.Contains(props, i.Name) || slices.Contains(props, strings.TrimPrefix(i.Name, "_")) TODO: use this instead
				return slices.Contains(props, strings.TrimPrefix(i.Name, "_"))
			})
			// remove methods that are property getter/setter
			class.InstanceMethods = slices.DeleteFunc(class.InstanceMethods, func(m objc.Method) bool {
				return slices.Contains(props, m.Name) || slices.Contains(setters, m.Name)
			})
			fname := filepath.Join(o.conf.Output, o.conf.Name, class.Name+".h")
			if err := writeHeader(&headerInfo{
				FileName:      fname,
				IpswVersion:   o.conf.IpswVersion,
				BuildVersions: buildVersions,
				SourceVersion: sourceVersion,
				Name:          class.Name,
				Imports:       imps[class.Name],
				Object:        swift.DemangleBlob(class.Verbose()),
			}); err != nil {
				return err
			}
			headers = append(headers, filepath.Base(fname))
		}

		/* generate ObjC protocol headers */
		protos, err := m.GetObjCProtocols()
		if err != nil {
			if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				return err
			}
		}
		slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
			return cmp.Compare(a.Name, b.Name)
		})
		seen := make(map[uint64]bool)
		for _, proto := range protos {
			if !slices.Contains(baseFrameworks, o.conf.Name) {
				if _, found := slices.BinarySearch(o.baseFWs["protocols"], proto.Name); found {
					continue // skip Foundation protocols
				}
			}
			if _, ok := seen[proto.Ptr]; !ok { // prevent displaying duplicates
				var props []string
				var setters []string
				for _, prop := range proto.InstanceProperties {
					props = append(props, prop.Name)
					setters = append(setters, "set"+strings.ToUpper(prop.Name[:1])+prop.Name[1:]+":")
				}
				slices.Sort(props)
				slices.Sort(setters)
				// remove methods that are property getter/setter
				proto.InstanceMethods = slices.DeleteFunc(proto.InstanceMethods, func(m objc.Method) bool {
					return slices.Contains(props, m.Name) || slices.Contains(setters, m.Name)
				})
				proto.OptionalInstanceMethods = slices.DeleteFunc(proto.OptionalInstanceMethods, func(m objc.Method) bool {
					return slices.Contains(props, m.Name) || slices.Contains(setters, m.Name)
				})
				fname := filepath.Join(o.conf.Output, o.conf.Name, proto.Name+"-Protocol.h")
				if err := writeHeader(&headerInfo{
					FileName:      fname,
					IpswVersion:   o.conf.IpswVersion,
					BuildVersions: buildVersions,
					SourceVersion: sourceVersion,
					Name:          proto.Name + "_Protocol",
					Imports:       imps[proto.Name+"-Protocol"],
					Object:        swift.DemangleBlob(proto.Verbose()),
				}); err != nil {
					return err
				}
				headers = append(headers, filepath.Base(fname))
				seen[proto.Ptr] = true
			}
		}

		/* generate ObjC category headers */
		cats, err := m.GetObjCCategories()
		if err != nil {
			if !errors.Is(err, macho.ErrObjcSectionNotFound) {
				return err
			}
		}
		slices.SortStableFunc(cats, func(a, b objc.Category) int {
			return cmp.Compare(a.Name, b.Name)
		})
		for _, cat := range cats {
			fname := filepath.Join(o.conf.Output, o.conf.Name, cat.Name+".h")
			if cat.Class != nil && cat.Class.Name != "" {
				fname = filepath.Join(o.conf.Output, o.conf.Name, cat.Class.Name+"+"+cat.Name+".h")
			}
			var name string
			if cat.Class != nil && cat.Class.Name != "" {
				name = cat.Class.Name + "_" + cat.Name
			} else {
				name = cat.Name
			}
			if err := writeHeader(&headerInfo{
				FileName:      fname,
				IpswVersion:   o.conf.IpswVersion,
				BuildVersions: buildVersions,
				SourceVersion: sourceVersion,
				Name:          name,
				Imports:       imps[cat.Name],
				Object:        swift.DemangleBlob(cat.Verbose()),
			}); err != nil {
				return err
			}
			headers = append(headers, filepath.Base(fname))
		}

		/* generate umbrella header */
		if len(headers) > 0 {
			var umbrella string
			if slices.Contains(headers, o.conf.Name+".h") {
				umbrella = o.conf.Name + "-Umbrella"
			} else {
				umbrella = o.conf.Name
			}

			for i, header := range headers {
				headers[i] = "#import \"" + header + "\""
			}

			fname := filepath.Join(o.conf.Output, o.conf.Name, umbrella+".h")
			if err := writeHeader(&headerInfo{
				FileName:      fname,
				IpswVersion:   o.conf.IpswVersion,
				BuildVersions: buildVersions,
				SourceVersion: sourceVersion,
				IsUmbrella:    true,
				Name:          strings.ReplaceAll(umbrella, "-", "_"),
				Object:        strings.Join(headers, "\n") + "\n",
			}); err != nil {
				return err
			}
		}

		return nil
	}

	if len(o.deps) > 0 {
		for _, m := range o.deps {
			if err := writeHeaders(m); err != nil {
				return err
			}
		}
	}

	return writeHeaders(o.file)
}

type XCFrameworkAvailableLibrary struct {
	BinaryPath               string   `plist:"BinaryPath"`
	LibraryIdentifier        string   `plist:"LibraryIdentifier"`
	LibraryPath              string   `plist:"libraryPath"`
	SupportedArchitectures   []string `plist:"SupportedArchitectures"`
	SupportedPlatform        string   `plist:"SupportedPlatform"`
	SupportedPlatformVariant string   `plist:"SupportedPlatformVariant,omitempty"`
}

type XCFrameworkInfoPlist struct {
	AvailableLibraries       []XCFrameworkAvailableLibrary `plist:"AvailableLibraries"`
	CFBundlePackageType      string                        `plist:"CFBundlePackageType"`
	XCFrameworkFormatVersion string                        `plist:"XCFrameworkFormatVersion"`
}
type XCFrameworkLibraryInfoPlist struct {
	BuildMachineOSBuild           string   `plist:"BuildMachineOSBuild"`
	CFBundleDevelopmentRegion     string   `plist:"CFBundleDevelopmentRegion"`
	CFBundleExecutable            string   `plist:"CFBundleExecutable"`
	CFBundleIdentifier            string   `plist:"CFBundleIdentifier"`
	CFBundleInfoDictionaryVersion string   `plist:"CFBundleInfoDictionaryVersion"`
	CFBundleName                  string   `plist:"CFBundleName"`
	CFBundlePackageType           string   `plist:"CFBundlePackageType"`
	CFBundleShortVersionString    string   `plist:"CFBundleShortVersionString"`
	CFBundleSignature             string   `plist:"CFBundleSignature"`
	CFBundleSupportedPlatforms    []string `plist:"CFBundleSupportedPlatforms"`
	CFBundleVersion               string   `plist:"CFBundleVersion"`
	DTCompiler                    string   `plist:"DTCompiler"`
	DTPlatformBuild               string   `plist:"DTPlatformBuild"`
	DTPlatformName                string   `plist:"DTPlatformName"`
	DTPlatformVersion             string   `plist:"DTPlatformVersion"`
	DTSDKBuild                    string   `plist:"DTSDKBuild"`
	DTSDKName                     string   `plist:"DTSDKName"`
	DTXcode                       string   `plist:"DTXcode"`
	DTXcodeBuild                  string   `plist:"DTXcodeBuild"`
	LSMinimumSystemVersion        string   `plist:"LSMinimumSystemVersion,omitempty"`
	MinimumOSVersion              string   `plist:"MinimumOSVersion,omitempty"`
	UIDeviceFamily                []uint64 `plist:"UIDeviceFamily,omitempty"`
}

type XCFrameworkConfig struct {
	LibraryIdentifier        string
	SupportedArchitectures   []string
	SupportedPlatform        string
	SupportedPlatformVariant string
	CFBundleVersion          string
	DTPlatformVersion        string
	LSMinimumSystemVersion   string
}

// XCFramework outputs and XCFramework for a DSC dylib
func (o *ObjC) XCFramework() error {
	var xcfw XCFrameworkConfig

	xcfolder := filepath.Join(o.conf.Output, o.conf.Name+".xcframework")
	if err := os.MkdirAll(xcfolder, 0o750); err != nil {
		return fmt.Errorf("failed to create XCFramework folder: %w", err)
	}

	image, err := o.cache.Image(o.conf.Name)
	if err != nil {
		return fmt.Errorf("failed to get image %s: %w", o.conf.Name, err)
	}
	m, err := image.GetMacho()
	if err != nil {
		return fmt.Errorf("failed to get macho from image %s: %w", o.conf.Name, err)
	}

	if bvs := m.BuildVersions(); len(bvs) == 0 { // TODO: support universal MachOs (with multiple architectures)
		return fmt.Errorf("no build versions found in %s", o.conf.Name)
	} else {
		for _, bv := range bvs {
			switch bv.Platform {
			case types.Platform_iOsSimulator, types.Platform_tvOsSimulator, types.Platform_watchOsSimulator, types.Platform_visionOsSimulator:
				xcfw.LibraryIdentifier += "_simulator"
				xcfw.SupportedPlatformVariant = "simulator"
			default:
				xcfw.LibraryIdentifier += strings.ToLower(bv.Platform.String())
				xcfw.SupportedPlatform = strings.ToLower(bv.Platform.String())
				xcfw.DTPlatformVersion = bv.Sdk.String()
				xcfw.LSMinimumSystemVersion = bv.Minos.String()
				switch m.CPU {
				case types.CPUAmd64:
					xcfw.LibraryIdentifier += "_x86_64"
					xcfw.SupportedArchitectures = append(xcfw.SupportedArchitectures, "x86_64")
				case types.CPUArm64:
					if m.SubCPU.String(m.CPU) == "arm64e" {
						xcfw.LibraryIdentifier += "_arm64e"
					} else {
						xcfw.LibraryIdentifier += "_arm64"
					}
				}
			}
		}
	}

	if id := m.DylibID(); id != nil {
		xcfw.CFBundleVersion = id.CurrentVersion.String()
	}

	/* generate XCFramework Info.plist */
	f, err := os.Create(filepath.Join(xcfolder, "Info.plist"))
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Join(xcfolder, "Info.plist"), err)
	}
	defer f.Close()

	enc := plist.NewEncoder(f)
	enc.Indent("    ")
	if err := enc.Encode(XCFrameworkInfoPlist{
		AvailableLibraries: []XCFrameworkAvailableLibrary{
			{
				BinaryPath:               o.conf.Name + ".framework/" + o.conf.Name + ".tbd",
				LibraryIdentifier:        xcfw.LibraryIdentifier,
				LibraryPath:              o.conf.Name + ".framework",
				SupportedArchitectures:   xcfw.SupportedArchitectures,
				SupportedPlatform:        xcfw.SupportedPlatform,
				SupportedPlatformVariant: xcfw.SupportedPlatformVariant,
			},
		},
		CFBundlePackageType:      "XFWK",
		XCFrameworkFormatVersion: "1.0",
	}); err != nil {
		return fmt.Errorf("failed to create XCFramework Info.plist")
	}

	/* create folder structure */
	fwfolder := filepath.Join(xcfolder, xcfw.LibraryIdentifier, o.conf.Name+".framework")
	if err := os.MkdirAll(filepath.Join(fwfolder, "Headers"), 0o750); err != nil {
		return fmt.Errorf("failed to create Headers folder: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(fwfolder, "Modules"), 0o750); err != nil {
		return fmt.Errorf("failed to create Modules folder: %w", err)
	}

	/* generate framework tbd */
	var reexports []string
	if rexps := m.GetLoadsByName("LC_REEXPORT_DYLIB"); len(rexps) > 0 {
		for _, rexp := range rexps {
			reexports = append(reexports, rexp.(*macho.ReExportDylib).Name)
		}
	}
	t, err := tbd.NewTBD(image, reexports, false, false)
	if err != nil {
		return fmt.Errorf("failed to create tbd: %w", err)
	}
	outTBD, err := t.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate tbd: %w", err)
	}
	outTBD += "...\n"
	tbdFile := filepath.Join(fwfolder, o.conf.Name+".tbd")
	if err = os.WriteFile(tbdFile, []byte(outTBD), 0o660); err != nil {
		return fmt.Errorf("failed to write tbd file %s: %v", tbdFile, err)
	}

	/* generate modulemap */
	if err := os.WriteFile(filepath.Join(fwfolder, "Modules", "module.modulemap"), []byte(fmt.Sprintf(
		"module %s [system] {\n"+
			"    header \"Headers/%s.h\"\n"+ // NOTE: this SHOULD be the umbrella header
			"    export *\n"+
			"}\n", o.conf.Name, o.conf.Name,
	)), 0o660); err != nil {
		return fmt.Errorf("failed to write module.modulemap file: %v", err)
	}

	/* generate XCFramework Library Info.plist */
	f2, err := os.Create(filepath.Join(fwfolder, "Info.plist"))
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Join(fwfolder, "Info.plist"), err)
	}
	defer f2.Close()
	enc = plist.NewEncoder(f2)
	enc.Indent("    ")
	if err := enc.Encode(XCFrameworkLibraryInfoPlist{
		BuildMachineOSBuild:           "23E224",
		CFBundleDevelopmentRegion:     "en",
		CFBundleExecutable:            o.conf.Name + ".tbd",
		CFBundleIdentifier:            "com.apple." + strings.ToLower(o.conf.Name),
		CFBundleInfoDictionaryVersion: "6.0",
		CFBundleName:                  o.conf.Name,
		CFBundlePackageType:           "FMWK",
		CFBundleShortVersionString:    "1.0",
		CFBundleSignature:             "????",
		CFBundleVersion:               xcfw.CFBundleVersion,
		DTCompiler:                    "com.apple.compilers.llvm.clang.1_0",
		CFBundleSupportedPlatforms:    []string{xcfw.SupportedPlatform}, // TODO: add variants (or universal dylib/macho support)
		DTPlatformName:                xcfw.SupportedPlatform,
		DTPlatformVersion:             xcfw.DTPlatformVersion,
		DTPlatformBuild:               "",
		DTSDKBuild:                    "23E224",
		DTSDKName:                     fmt.Sprintf("%s%s.internal", xcfw.SupportedPlatform, xcfw.DTPlatformVersion),
		DTXcode:                       "1500",
		DTXcodeBuild:                  "15E6079e", // XCode 15.3
		LSMinimumSystemVersion:        xcfw.LSMinimumSystemVersion,
	}); err != nil {
		return fmt.Errorf("failed to create XCFramework Info.plist")
	}

	/* generate Headers */
	o.conf.Headers = true
	o.conf.Output = filepath.Join(fwfolder, "Headers")
	return o.Headers()
}

func (o *ObjC) SwiftPackage() error {
	return fmt.Errorf("not implemented yet (coming soon)")
}

/* utils */

func writeHeader(hdr *headerInfo) error {
	out := fmt.Sprintf(
		"//\n"+
			"//   Generated by https://github.com/blacktop/ipsw (%s)\n"+
			"//\n"+
			"//    - LC_BUILD_VERSION:  %s\n"+
			"//    - LC_SOURCE_VERSION: %s\n"+
			"//\n"+
			"#ifndef %s_h\n"+
			"#define %s_h\n",
		hdr.IpswVersion,
		strings.Join(hdr.BuildVersions, "\n//    - LC_BUILD_VERSION:  "),
		hdr.SourceVersion,
		hdr.Name,
		hdr.Name)
	if !hdr.IsUmbrella {
		out += "@import Foundation;\n"
	}
	out += "\n"
	if len(hdr.Imports.Imports) > 0 {
		for _, imp := range hdr.Imports.Imports {
			out += fmt.Sprintf("#include \"%s\"\n", imp)
		}
	}
	if len(hdr.Imports.Locals) > 0 {
		for _, local := range hdr.Imports.Locals {
			out += fmt.Sprintf("#include \"%s\"\n", local)
		}
	}
	if len(hdr.Imports.Imports) > 0 || len(hdr.Imports.Locals) > 0 {
		out += "\n"
	}
	if len(hdr.Imports.Classes) > 0 {
		out += fmt.Sprintf("@class %s;\n", strings.Join(hdr.Imports.Classes, ", "))
	}
	if len(hdr.Imports.Protos) > 0 {
		out += fmt.Sprintf("@protocol %s;\n", strings.Join(hdr.Imports.Protos, ", "))
	}
	if len(hdr.Imports.Classes) > 0 || len(hdr.Imports.Protos) > 0 {
		out += "\n"
	}
	out += fmt.Sprintf("%s\n", hdr.Object)
	out += fmt.Sprintf("#endif /* %s_h */\n", hdr.Name)

	if err := os.MkdirAll(filepath.Dir(hdr.FileName), 0o750); err != nil {
		return err
	}
	log.Infof("Creating %s", hdr.FileName)
	if err := os.WriteFile(hdr.FileName, []byte(out), 0644); err != nil {
		return fmt.Errorf("failed to write header %s: %v", hdr.FileName, err)
	}

	return nil
}

func (o *ObjC) processForwardDeclarations(m *macho.File) (map[string]Imports, error) {
	var classNames []string
	var protoNames []string

	imps := make(map[string]Imports)

	classes, err := m.GetObjCClasses()
	if err != nil {
		if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return nil, err
		}
	}
	slices.SortStableFunc(classes, func(a, b objc.Class) int {
		return cmp.Compare(a.Name, b.Name)
	})
	for _, class := range classes {
		classNames = append(classNames, class.Name)
	}

	protos, err := m.GetObjCProtocols()
	if err != nil {
		if !errors.Is(err, macho.ErrObjcSectionNotFound) {
			return nil, err
		}
	}
	slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
		return cmp.Compare(a.Name, b.Name)
	})
	for _, proto := range protos {
		protoNames = append(protoNames, proto.Name)
	}

	for _, class := range classes {
		var imp Imports
		if superClass := class.SuperClass; superClass != "" {
			if slices.Contains(classNames, superClass) {
				imp.Locals = append(imp.Locals, superClass+".h")
			} else {
				imp.Classes = append(imp.Classes, superClass)
			}
		}
		for _, prot := range class.Protocols {
			if slices.Contains(protoNames, prot.Name) {
				imp.Locals = append(imp.Locals, prot.Name+"-Protocol.h")
			} else {
				imp.Protos = append(imp.Protos, prot.Name)
			}
		}
		for _, ivar := range class.Ivars {
			typ, _ := strings.CutSuffix(ivar.Verbose(), ivar.Name+";")
			o.fillImportsForType(typ, class.Name, "", classNames, protoNames, &imp)
		}
		for _, prop := range class.Props {
			typ := prop.Type()
			o.fillImportsForType(typ, class.Name, "", classNames, protoNames, &imp)
		}
		for _, method := range class.InstanceMethods {
			for i := 0; i < method.NumberOfArguments(); i++ {
				typ := method.ArgumentType(i)
				o.fillImportsForType(typ, class.Name, "", classNames, protoNames, &imp)
				if i == 0 {
					i += 2
				}
			}
		}
		for _, method := range class.ClassMethods {
			for i := 0; i < method.NumberOfArguments(); i++ {
				typ := method.ArgumentType(i)
				o.fillImportsForType(typ, class.Name, "", classNames, protoNames, &imp)
				if i == 0 {
					i += 2
				}
			}
		}
		imp.uniq(o.baseFWs)
		imps[class.Name] = imp
	}

	for _, proto := range protos {
		var imp Imports
		for _, prot := range proto.Prots {
			if slices.Contains(protoNames, prot.Name) {
				imp.Locals = append(imp.Locals, prot.Name+"-Protocol.h")
			} else {
				imp.Protos = append(imp.Protos, prot.Name)
			}
		}
		for _, prop := range proto.InstanceProperties {
			typ := prop.Type()
			o.fillImportsForType(typ, "", proto.Name, classNames, protoNames, &imp)
		}
		for _, method := range proto.InstanceMethods {
			for i := 0; i < method.NumberOfArguments(); i++ {
				typ := method.ArgumentType(i)
				o.fillImportsForType(typ, "", proto.Name, classNames, protoNames, &imp)
				if i == 0 {
					i += 2
				}
			}
		}
		for _, method := range proto.ClassMethods {
			for i := 0; i < method.NumberOfArguments(); i++ {
				typ := method.ArgumentType(i)
				o.fillImportsForType(typ, "", proto.Name, classNames, protoNames, &imp)
				if i == 0 {
					i += 2
				}
			}
		}
		for _, method := range proto.OptionalInstanceMethods {
			for i := 0; i < method.NumberOfArguments(); i++ {
				typ := method.ArgumentType(i)
				o.fillImportsForType(typ, "", proto.Name, classNames, protoNames, &imp)
				if i == 0 {
					i += 2
				}
			}
		}
		for _, method := range proto.OptionalClassMethods {
			for i := 0; i < method.NumberOfArguments(); i++ {
				typ := method.ArgumentType(i)
				o.fillImportsForType(typ, "", proto.Name, classNames, protoNames, &imp)
				if i == 0 {
					i += 2
				}
			}
		}
		imp.uniq(o.baseFWs)
		imps[proto.Name+"-Protocol"] = imp
	}

	return imps, nil
}

func (o *ObjC) scanBaseFrameworks() error {
	o.baseFWs["classes"] = []string{}
	o.baseFWs["protocols"] = []string{}
	if o.cache != nil {
		for _, name := range baseFrameworks {
			img, err := o.cache.Image(name)
			if err != nil {
				return err
			}
			m, err := img.GetMacho()
			if err != nil {
				return err
			}

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
				o.baseFWs["classes"] = append(o.baseFWs["classes"], class.Name)
			}

			protos, err := m.GetObjCProtocols()
			if err != nil {
				if !errors.Is(err, macho.ErrObjcSectionNotFound) {
					return err
				}
			}
			slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
				return cmp.Compare(a.Name, b.Name)
			})
			for _, proto := range protos {
				o.baseFWs["protocols"] = append(o.baseFWs["protocols"], proto.Name)
			}
			slices.Sort(o.baseFWs["classes"])
			slices.Sort(o.baseFWs["protocols"])
		}
	}
	return nil
}

func (o *ObjC) fillImportsForType(typ string, className string, protoName string, classNames []string, protoNames []string, imp *Imports) {
	typ = strings.Trim(typ, ` *`)

	if !strings.ContainsAny(typ, "<>") {
		typ := o.nonBuiltInType(typ)
		if typ == "" {
			return
		}

		if !slices.Contains(classNames, typ) {
			imp.Classes = append(imp.Classes, typ)
			return
		}

		if typ != className {
			imp.Locals = append(imp.Locals, typ+".h")
			return
		}

		return
	}

	if !strings.HasPrefix(typ, "<") {
		before, after, _ := strings.Cut(typ, "<")

		o.fillImportsForType(before, className, protoName, classNames, protoNames, imp)
		o.fillImportsForType("<"+after, className, protoName, classNames, protoNames, imp)

		return
	}

	if !strings.HasSuffix(typ, ">") {
		before, after, _ := strings.Cut(typ, ">")

		o.fillImportsForType(before+">", className, protoName, classNames, protoNames, imp)
		o.fillImportsForType(after, className, protoName, classNames, protoNames, imp)

		return
	}

	for _, typ := range strings.Split(strings.Trim(typ, "<>"), ", ") {
		if !slices.Contains(protoNames, typ) {
			imp.Protos = append(imp.Protos, typ)
			continue
		}

		if typ != protoName {
			imp.Locals = append(imp.Locals, typ+"-Protocol.h")
		}
	}
}

func (o *ObjC) nonBuiltInType(typ string) string {
	if typ == "" {
		return ""
	}

	if strings.ContainsAny(typ, "()[]{};") {
		return ""
	}

	switch before, after, _ := strings.Cut(typ, " "); before {
	case "_Bool", "_Complex", "_Imaginary", "BOOL", "Class", "IMP", "Ivar", "Method", "SEL", "bool", "char", "class", "double", "enum", "float", "id", "int", "long", "short", "signed", "struct", "union", "unsigned", "void":
		return ""

	case "_Atomic", "bycopy", "byref", "const", "in", "inout", "oneway", "out", "restrict", "volatile":
		return o.nonBuiltInType(after)
	}

	return typ
}
