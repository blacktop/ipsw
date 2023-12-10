// Package macho provides functionality for parsing Mach-O files.
package macho

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"

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
	Verbose  bool
	Addrs    bool
	Arch     string
	Objc     bool
	Swift    bool
	Color    bool
	Theme    string
	Demangle bool
	ObjcRefs bool
}

func GetClass(m *macho.File, pattern string, conf *Config) (out string, err error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to compile regex: %v", err)
	}

	classes, err := m.GetObjCClasses()
	if err != nil {
		if errors.Is(err, macho.ErrObjcSectionNotFound) {
			return "", nil
		}
		return "", err
	}

	slices.SortStableFunc(classes, func(a, b objc.Class) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, class := range classes {
		if re.MatchString(class.Name) {
			if conf.Color {
				quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", conf.Theme)
				quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
			} else {
				fmt.Println(swift.DemangleBlob(class.Verbose()))
			}
		}
	}

	return
}

func GetProtocol(m *macho.File, pattern string, conf *Config) (out string, err error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to compile regex: %v", err)
	}

	protos, err := m.GetObjCProtocols()
	if err != nil {
		if errors.Is(err, macho.ErrObjcSectionNotFound) {
			return "", nil
		}
		return "", err
	}

	slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
		return cmp.Compare(a.Name, b.Name)
	})
	seen := make(map[uint64]bool)

	for _, proto := range protos {
		if re.MatchString(proto.Name) {
			if conf.Color {
				quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", conf.Theme)
				quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
			} else {
				fmt.Println(swift.DemangleBlob(proto.Verbose()))
			}
			seen[proto.Ptr] = true
		}
	}

	return
}

func GetCategory(m *macho.File, pattern string, conf *Config) (out string, err error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("failed to compile regex: %v", err)
	}

	cats, err := m.GetObjCCategories()
	if err != nil {
		if errors.Is(err, macho.ErrObjcSectionNotFound) {
			return "", nil
		}
		return "", err
	}

	slices.SortStableFunc(cats, func(a, b objc.Category) int {
		return cmp.Compare(a.Name, b.Name)
	})

	for _, cat := range cats {
		if re.MatchString(cat.Name) {
			if conf.Color {
				quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", conf.Theme)
				quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
			} else {
				fmt.Println(swift.DemangleBlob(cat.Verbose()))
			}
		}
	}

	return
}

// Dump outputs ObjC info from a MachO
func Dump(m *macho.File, conf *Config) (out string, err error) {
	if !m.HasObjC() {
		return "no objc", ErrNoObjc
	}
	if conf.Theme == "" {
		conf.Theme = "nord"
	}

	if info, err := m.GetObjCImageInfo(); err == nil {
		fmt.Println(info.Flags)
	} else if !errors.Is(err, macho.ErrObjcSectionNotFound) {
		log.Error(err.Error())
	}
	if conf.Verbose {
		fmt.Println(m.GetObjCToc())
	}
	if protos, err := m.GetObjCProtocols(); err == nil {
		slices.SortStableFunc(protos, func(a, b objc.Protocol) int {
			return cmp.Compare(a.Name, b.Name)
		})
		seen := make(map[uint64]bool)
		for _, proto := range protos {
			if _, ok := seen[proto.Ptr]; !ok { // prevent displaying duplicates
				if conf.Verbose {
					if conf.Color {
						quick.Highlight(os.Stdout, swift.DemangleBlob(proto.Verbose()), "objc", "terminal256", conf.Theme)
						quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
					} else {
						fmt.Println(swift.DemangleBlob(proto.Verbose()))
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
		log.Error(err.Error())
	}
	if classes, err := m.GetObjCClasses(); err == nil {
		slices.SortStableFunc(classes, func(a, b objc.Class) int {
			return cmp.Compare(a.Name, b.Name)
		})
		for _, class := range classes {
			if conf.Verbose {
				if conf.Color {
					quick.Highlight(os.Stdout, swift.DemangleBlob(class.Verbose()), "objc", "terminal256", conf.Theme)
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
				} else {
					fmt.Println(swift.DemangleBlob(class.Verbose()))
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
		log.Error(err.Error())
	}
	if cats, err := m.GetObjCCategories(); err == nil {
		slices.SortStableFunc(cats, func(a, b objc.Category) int {
			return cmp.Compare(a.Name, b.Name)
		})
		for _, cat := range cats {
			if conf.Verbose {
				if conf.Color {
					quick.Highlight(os.Stdout, swift.DemangleBlob(cat.Verbose()), "objc", "terminal256", conf.Theme)
					quick.Highlight(os.Stdout, "\n/****************************************/\n\n", "objc", "terminal256", conf.Theme)
				} else {
					fmt.Println(swift.DemangleBlob(cat.Verbose()))
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
		log.Error(err.Error())
	}
	if conf.ObjcRefs {
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
		if conf.Verbose {
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

	return
}

// Headers outputs ObjC class-dump headers from a MachO
func Headers(m *macho.File, conf *Config) error {
	if !m.HasObjC() {
		return ErrNoObjc
	}

	return nil
}
