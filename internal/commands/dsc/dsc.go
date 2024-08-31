// Package dsc implements the `dsc` commands
package dsc

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/codesign"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/internal/commands/mount"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/tbd"
)

// ImportedBy is a struct that contains information about which dyld_shared_cache dylibs import a given dylib
// swagger:model
type ImportedBy struct {
	DSC  []string `json:"dsc,omitempty"`
	Apps []string `json:"apps,omitempty"`
}

// Dylib is a struct that contains information about a dyld_shared_cache dylib
// swagger:model
type Dylib struct {
	Index       int    `json:"index,omitempty"`
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	LoadAddress uint64 `json:"load_address,omitempty"`
}

// Info is a struct that contains information about a dyld_shared_cache file
// swagger:model
type Info struct {
	Magic              string                                      `json:"magic,omitempty"`
	UUID               string                                      `json:"uuid,omitempty"`
	Platform           string                                      `json:"platform,omitempty"`
	MaxSlide           int                                         `json:"max_slide,omitempty"`
	SubCacheArrayCount int                                         `json:"num_sub_caches,omitempty"`
	SubCacheGroupID    int                                         `json:"sub_cache_group_id,omitempty"`
	SymSubCacheUUID    string                                      `json:"sym_sub_cache_uuid,omitempty"`
	Mappings           map[string][]dyld.CacheMappingWithSlideInfo `json:"mappings,omitempty"`
	CodeSignature      map[string]codesign.CodeSignature           `json:"code_signature,omitempty"`
	Dylibs             []Dylib                                     `json:"dylibs,omitempty"`
}

// Symbol is a struct that contains information about a dyld_shared_cache symbol
// swagger:model
type Symbol struct {
	// The address of the symbol
	Address uint64 `json:"address,omitempty"`
	// The name of the symbol
	Name string `json:"name,omitempty"`
	// The type of the symbol
	Type string `json:"type,omitempty"`
	// The image that contains the symbol
	Image string `json:"image,omitempty"`
	// The lookup pattern used to find the symbol
	//
	// required: true
	Pattern string `json:"pattern,omitempty"`
}

// SymbolLookup is a struct that contains information about a dyld_shared_cache symbol lookup
type SymbolLookup struct {
	// The address of the symbol
	Address uint64 `json:"address,omitempty"`
	// The symbol name
	Symbol string `json:"symbol,omitempty"`
	// The demangled symbol name
	Demanged string `json:"demanged,omitempty"`
	// The DSC mapping name
	Mapping string `json:"mapping,omitempty"`
	// The DSC sub-cache UUID
	UUID string `json:"uuid,omitempty"`
	// Is the symbol in a DSC stub island
	StubIsland bool `json:"stub_island,omitempty"`
	// The DSC sub-cache file extension
	Extension string `json:"ext,omitempty"`
	// The containing image name
	Image string `json:"image,omitempty"`
	// The containing image section
	Section string `json:"section,omitempty"`
	// The containing image segment
	Segment string `json:"segment,omitempty"`
}

// String is a struct that contains information about a dyld_shared_cache string
// swagger:model
type String struct {
	Offset  uint64 `json:"offset,omitempty"`
	Address uint64 `json:"address,omitempty"`
	Mapping string `json:"mapping,omitempty"`
	Image   string `json:"image,omitempty"`
	String  string `json:"string,omitempty"`
}

// swagger:model
type subCache struct {
	// the DSC sub-cache UUID
	UUID string `json:"uuid"`
	// the DSC sub-cache file extension
	Extension string `json:"ext"`
	// is the offset in a DSC stub island
	InStubs bool `json:"stubs"`
	// the DSC sub-cache mapping name
	Mapping string `json:"mapping"`
}

// swagger:model
type offset struct {
	// the file offset in the DSC sub-cache
	Offset uint64 `json:"offset"`
	// the DSC sub-cache
	// swagger:allOf
	SubCache subCache `json:"sub_cache"`
}

// Offset is a struct that contains information about a dyld_shared_cache offset
// swagger:model
type Offset struct {
	// the file offset
	File *offset `json:"file,omitempty"`
	// the vmcache offset
	Cache *offset `json:"cache,omitempty"`
}

// swagger:model
type address struct {
	// the offset in the DSC sub-cache
	Address uint64 `json:"address"`
	// the DSC sub-cache
	// swagger:allOf
	SubCache subCache `json:"sub_cache"`
}

// Address is a struct that contains information about a dyld_shared_cache address
// swagger:model
type Address struct {
	// the virtual addresses
	// swagger:allOf
	Files []*address `json:"files,omitempty"`
	// the vmcache address
	// swagger:allOf
	Cache *address `json:"cache,omitempty"`
}

// ConvertAddressToOffset converts a dyld_shared_cache address to an offset
func ConvertAddressToOffset(f *dyld.File, addr uint64) (*Offset, error) {

	uuid, off, err := f.GetOffset(addr)
	if err != nil {
		return nil, err
	}

	o := &Offset{
		File: &offset{
			Offset: off,
			SubCache: subCache{
				UUID: uuid.String(),
			},
		},
	}

	m, err := f.GetMappingForOffsetForUUID(uuid, off)
	if err != nil {
		return nil, err
	}

	o.File.SubCache.Mapping = m.Name

	if f.IsDyld4 {
		o.File.SubCache.Extension, _ = f.GetSubCacheExtensionFromUUID(uuid)
		if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
			o.File.SubCache.InStubs = true
		}
	}

	if f.Headers[f.UUID].CacheType == dyld.CacheTypeUniversal {
		uuid, off, err := f.GetCacheOffsetFromAddress(addr)
		if err != nil {
			return nil, err
		}
		o.Cache = &offset{
			Offset: off,
			SubCache: subCache{
				UUID: uuid.String(),
			},
		}

		if m, err := f.GetMappingForOffsetForUUID(uuid, o.File.Offset); err == nil {
			o.Cache.SubCache.Mapping = m.Name
		} else {
			o.Cache.SubCache.Mapping = "?"
		}

		if f.IsDyld4 {
			o.Cache.SubCache.Extension, _ = f.GetSubCacheExtensionFromUUID(uuid)
			if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
				o.Cache.SubCache.InStubs = true
			}
		}
	}

	return o, nil
}

// ConvertOffsetToAddress converts a dyld_shared_cache offset to an address
func ConvertOffsetToAddress(f *dyld.File, offset uint64) (*Address, error) {
	a := &Address{}

	for uuid := range f.MappingsWithSlideInfo {
		addr, err := f.GetVMAddressForUUID(uuid, offset)
		if err != nil {
			continue
		}
		aa := &address{
			Address: addr,
			SubCache: subCache{
				UUID: uuid.String(),
			},
		}
		// break
		uuid, m, err := f.GetMappingForVMAddress(aa.Address)
		if err != nil {
			return nil, err
		}

		aa.SubCache.Mapping = m.Name

		if f.IsDyld4 {
			aa.SubCache.Extension, _ = f.GetSubCacheExtensionFromUUID(uuid)
			if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
				aa.SubCache.InStubs = true
			}
		}
		a.Files = append(a.Files, aa)
	}

	if f.Headers[f.UUID].CacheType == dyld.CacheTypeUniversal {
		uuid, addr, err := f.GetCacheVMAddress(offset)
		if err != nil {
			return nil, err
		}
		a.Cache = &address{
			Address: addr,
			SubCache: subCache{
				UUID: uuid.String(),
			},
		}

		if _, m, err := f.GetMappingForVMAddress(addr); err == nil {
			a.Cache.SubCache.Mapping = m.Name
		} else {
			a.Cache.SubCache.Mapping = "?"
		}

		if f.IsDyld4 {
			a.Cache.SubCache.Extension, _ = f.GetSubCacheExtensionFromUUID(uuid)
			if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
				a.Cache.SubCache.InStubs = true
			}
		}
	}

	return a, nil
}

// LookupSymbol returns a dyld_shared_cache symbol for an address
func LookupSymbol(f *dyld.File, addr uint64) (*SymbolLookup, error) {
	var secondAttempt bool

	sym := &SymbolLookup{
		Address: addr,
	}

	uuid, mapping, err := f.GetMappingForVMAddress(addr)
	if err != nil {
		return nil, err
	}

	sym.UUID = uuid.String()
	sym.Mapping = mapping.Name

	sym.Extension, _ = f.GetSubCacheExtensionFromUUID(uuid)
	if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
		sym.StubIsland = true
	}

retry:
	if image, err := f.GetImageContainingVMAddr(addr); err == nil {
		m, err := image.GetMacho()
		if err != nil {
			return nil, err
		}
		defer m.Close()

		sym.Image = image.Name

		if s := m.FindSegmentForVMAddr(addr); s != nil {
			sym.Segment = s.Name
			if s.Nsect > 0 {
				if c := m.FindSectionForVMAddr(addr); c != nil {
					sym.Section = c.Name
				}
			}
		}

		// Load all symbols
		if err := image.Analyze(); err != nil {
			return nil, err
		}

		if fn, err := m.GetFunctionForVMAddr(addr); err == nil {
			delta := ""
			if addr-fn.StartAddr != 0 {
				delta = fmt.Sprintf(" + %d", addr-fn.StartAddr)
			}
			if symName, ok := f.AddressToSymbol[fn.StartAddr]; ok {
				if secondAttempt {
					symName = "_ptr." + symName
				}
				sym.Symbol = fmt.Sprintf("%s%s", symName, delta)
				return sym, nil
			}
			if secondAttempt {
				sym.Symbol = fmt.Sprintf("_ptr.func_%x%s", fn.StartAddr, delta)
				return sym, nil
			}
			sym.Symbol = fmt.Sprintf("func_%x%s", fn.StartAddr, delta)
			return sym, nil
		}

		if cstr, ok := m.IsCString(addr); ok {
			if secondAttempt {
				sym.Symbol = fmt.Sprintf("_ptr.%#v", cstr)
				return sym, nil
			}
			sym.Symbol = fmt.Sprintf("%#v", cstr)
			return sym, nil
		}
	}

	if symName, ok := f.AddressToSymbol[addr]; ok {
		if secondAttempt {
			symName = "_ptr." + symName
		}
		sym.Symbol = symName
		return sym, nil
	}

	if secondAttempt {
		sym.Symbol = "?"
		return sym, nil
	}

	ptr, err := f.ReadPointerAtAddress(addr)
	if err != nil {
		return nil, err
	}

	utils.Indent(log.Debug, 2)(fmt.Sprintf("no symbol found (trying again with %#x as a pointer to %#x)", addr, f.SlideInfo.SlidePointer(ptr)))

	addr = f.SlideInfo.SlidePointer(ptr)

	secondAttempt = true

	goto retry
}

// GetDylibsThatImport returns a list of dylibs that import the given dylib
func GetDylibsThatImport(f *dyld.File, name string) (*ImportedBy, error) {
	var importedBy ImportedBy

	image, err := f.Image(name)
	if err != nil {
		return nil, fmt.Errorf("dylib not in DSC: %v", err)
	}

	if f.SupportsDylibPrebuiltLoader() {
		for _, img := range f.Images {
			pbl, err := f.GetDylibPrebuiltLoader(img.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to get prebuilt loader for %s: %v", filepath.Base(img.Name), err)
			}
			for _, dep := range pbl.Dependents {
				if strings.EqualFold(dep.Name, image.Name) {
					importedBy.DSC = append(importedBy.DSC, img.Name)
				}
			}
		}
	} else {
		for _, img := range f.Images {
			m, err := img.GetPartialMacho()
			if err != nil {
				return nil, fmt.Errorf("failed to create partial MachO for image %s: %v", filepath.Base(img.Name), err)
			}
			for _, imp := range m.ImportedLibraries() {
				if strings.EqualFold(imp, image.Name) {
					importedBy.DSC = append(importedBy.DSC, img.Name)
				}
			}
			m.Close()
		}
	}

	if f.SupportsPrebuiltLoaderSet() {
		if err := f.ForEachLaunchLoaderSet(func(execPath string, pset *dyld.PrebuiltLoaderSet) {
			for _, loader := range pset.Loaders {
				for _, dep := range loader.Dependents {
					if strings.EqualFold(dep.Name, image.Name) {
						if execPath != loader.Path {
							importedBy.Apps = append(importedBy.Apps, fmt.Sprintf("%s (%s)", execPath, loader.Path))
						} else {
							importedBy.Apps = append(importedBy.Apps, execPath)
						}
					}
				}
			}
		}); err != nil {
			return nil, fmt.Errorf("failed to get prebuilt loader set: %v", err)
		}
	}

	return &importedBy, nil
}

// GetInfo returns a Info struct for a given dyld_shared_cache file
func GetInfo(f *dyld.File) (*Info, error) {
	info := &Info{
		Magic:    f.Headers[f.UUID].Magic.String(),
		UUID:     f.UUID.String(),
		Platform: f.Headers[f.UUID].Platform.String(),
		MaxSlide: int(f.Headers[f.UUID].MaxSlide),
	}

	info.Mappings = make(map[string][]dyld.CacheMappingWithSlideInfo)

	for u, mp := range f.MappingsWithSlideInfo {
		for _, m := range mp {
			info.Mappings[u.String()] = append(info.Mappings[u.String()], *m)
		}
	}

	info.CodeSignature = make(map[string]codesign.CodeSignature)

	for u, cs := range f.CodeSignatures {
		info.CodeSignature[u.String()] = *cs
	}

	for idx, img := range f.Images {
		m, err := img.GetPartialMacho()
		if err != nil {
			continue
			// return fmt.Errorf("failed to create partial MachO for image %s: %v", img.Name, err)
		}
		info.Dylibs = append(info.Dylibs, Dylib{
			Index:       idx + 1,
			Name:        img.Name,
			Version:     m.SourceVersion().Version.String(),
			UUID:        m.UUID().String(),
			LoadAddress: img.Info.Address,
		})
		m.Close()
	}

	return info, nil
}

// GetSymbols returns a list of symbols from a dyld_shared_cache file for a given list of lookup symbol structs
func GetSymbols(f *dyld.File, lookups []Symbol) ([]Symbol, error) {
	var syms []Symbol

	// group syms by image
	sym2imgs := make(map[string][]Symbol)
	for _, lookup := range lookups {
		if len(lookup.Pattern) == 0 {
			return nil, fmt.Errorf("'pattern' cannot be empty ('pattern' field can just be the name of the symbol): %#v", lookup)
		}
		if len(lookup.Image) > 0 {
			image, err := f.Image(lookup.Image)
			if err != nil {
				return nil, fmt.Errorf("failed to get image %s: %v", lookup.Image, err)
			}
			sym2imgs[image.Name] = append(sym2imgs[image.Name], lookup)
		} else {
			sym2imgs["unknown"] = append(sym2imgs["unknown"], lookup)
		}
	}

	for imageName, lookups := range sym2imgs {
		if imageName == "unknown" {
			for _, lookup := range lookups {
				re, err := regexp.Compile(lookup.Pattern)
				if err != nil {
					return nil, fmt.Errorf("invalid regex for %v: %w", lookup, err)
				}
				for _, image := range f.Images {
					m, err := image.GetPartialMacho()
					if err != nil {
						return nil, err
					}
					if err := image.ParseLocalSymbols(false); err != nil {
						return nil, err
					}
					for _, lsym := range image.LocalSymbols {
						if re.MatchString(lsym.Name) {
							var sec string
							if lsym.Sect > 0 && int(lsym.Sect) <= len(m.Sections) {
								sec = fmt.Sprintf("%s.%s", m.Sections[lsym.Sect-1].Seg, m.Sections[lsym.Sect-1].Name)
							}
							syms = append(syms, Symbol{
								Name:    lsym.Name,
								Address: lsym.Value,
								Type:    lsym.Type.String(sec),
								Image:   filepath.Base(image.Name),
							})
						}
					}
					if err := image.ParsePublicSymbols(false); err != nil {
						return nil, err
					}
					for _, sym := range image.PublicSymbols {
						if re.MatchString(sym.Name) {
							syms = append(syms, Symbol{
								Name:    sym.Name,
								Address: sym.Address,
								Type:    sym.Type,
								Image:   filepath.Base(image.Name),
							})
						}
					}
				}
			}
		} else { // image is known
			image, err := f.Image(imageName)
			if err != nil {
				return nil, err
			}
			for _, lookup := range lookups {
				re, err := regexp.Compile(lookup.Pattern)
				if err != nil {
					return nil, fmt.Errorf("invalid regex for %v: %w", lookup, err)
				}
				m, err := image.GetPartialMacho()
				if err != nil {
					return nil, err
				}
				if err := image.ParseLocalSymbols(false); err != nil {
					return nil, err
				}
				for _, lsym := range image.LocalSymbols {
					if re.MatchString(lsym.Name) {
						var sec string
						if lsym.Sect > 0 && int(lsym.Sect) <= len(m.Sections) {
							sec = fmt.Sprintf("%s.%s", m.Sections[lsym.Sect-1].Seg, m.Sections[lsym.Sect-1].Name)
						}
						syms = append(syms, Symbol{
							Name:    lsym.Name,
							Address: lsym.Value,
							Type:    lsym.Type.String(sec),
							Image:   filepath.Base(image.Name),
						})
					}
				}
				if err := image.ParsePublicSymbols(false); err != nil {
					return nil, err
				}
				for _, sym := range image.PublicSymbols {
					if re.MatchString(sym.Name) {
						syms = append(syms, Symbol{
							Name:    sym.Name,
							Address: sym.Address,
							Type:    sym.Type,
							Image:   filepath.Base(image.Name),
						})
					}
				}
			}
		}
	}

	return syms, nil
}

// GetStrings returns a list of strings from a dyld_shared_cache file for a given regex pattern
func GetStrings(f *dyld.File, in ...string) ([]String, error) {
	var strs []String

	if len(in) == 0 {
		return nil, fmt.Errorf("search strings cannot be empty")
	}

	for _, search := range in {
		matches, err := f.Search([]byte(search))
		if err != nil {
			return nil, fmt.Errorf("failed to search for pattern: %v", err)
		}
		for uuid, ms := range matches {
			for _, match := range ms {
				s := String{Offset: match}
				if mapping, err := f.GetMappingForOffsetForUUID(uuid, match); err == nil {
					s.Mapping = mapping.Name
					if sc := f.GetSubCacheInfo(uuid); sc != nil {
						s.Mapping += fmt.Sprintf(", sub_cache (%s)", sc.Extention)
					}
				} else {
					if sc := f.GetSubCacheInfo(uuid); sc != nil {
						s.Mapping += fmt.Sprintf("sub_cache (%s)", sc.Extention)
					}
				}
				if str, err := f.GetCStringAtOffsetForUUID(uuid, match); err == nil {
					s.String = strings.TrimSuffix(strings.TrimSpace(str), "\n")
				}
				if addr, err := f.GetVMAddressForUUID(uuid, match); err == nil {
					s.Address = addr
					if image, err := f.GetImageContainingVMAddr(addr); err == nil {
						s.Image = filepath.Base(image.Name)
					}
				}
				strs = append(strs, s)
			}
		}
	}

	return strs, nil
}

func GetStringsRegex(f *dyld.File, pattern string) ([]String, error) {
	var strs []String

	if len(pattern) == 0 {
		return nil, fmt.Errorf("'pattern' cannot be empty")
	}

	strRE, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}

	for _, i := range f.Images {
		m, err := i.GetMacho()
		if err != nil {
			return nil, fmt.Errorf("failed to create MachO for image %s: %v", i.Name, err)
		}

		// cstrings
		for _, sec := range m.Sections {
			if sec.Flags.IsCstringLiterals() || sec.Seg == "__TEXT" && sec.Name == "__const" {
				uuid, off, err := f.GetOffset(sec.Addr)
				if err != nil {
					return nil, fmt.Errorf("failed to get offset for %s.%s: %v", sec.Seg, sec.Name, err)
				}
				dat, err := f.ReadBytesForUUID(uuid, int64(off), sec.Size)
				if err != nil {
					return nil, fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
				}

				csr := bytes.NewBuffer(dat)

				for {
					pos := sec.Addr + uint64(csr.Cap()-csr.Len())

					s, err := csr.ReadString('\x00')

					if err == io.EOF {
						break
					}

					if err != nil {
						return nil, fmt.Errorf("failed to read string: %v", err)
					}

					s = strings.Trim(s, "\x00")

					if len(s) > 0 {
						if (sec.Seg == "__TEXT" && sec.Name == "__const") && !utils.IsASCII(s) {
							continue // skip non-ascii strings when dumping __TEXT.__const
						}
						if strRE.MatchString(s) {
							strs = append(strs, String{
								Address: pos,
								Image:   filepath.Base(i.Name),
								String:  s,
							})
						}
					}
				}
			}
		}

		// objc cfstrings
		if cfstrs, err := m.GetCFStrings(); err == nil {
			if len(cfstrs) > 0 {
				for _, cfstr := range cfstrs {
					if strRE.MatchString(cfstr.Name) {
						strs = append(strs, String{
							Address: cfstr.Address,
							Image:   filepath.Base(i.Name),
							String:  cfstr.Name,
						})
					}
				}
			}
		}

		// swift small string literals
		if info, err := m.GetObjCImageInfo(); err == nil {
			if info != nil && info.HasSwift() {
				if ss, err := mcmd.FindSwiftStrings(m); err == nil {
					for addr, s := range ss {
						if strRE.MatchString(s) {
							strs = append(strs, String{
								Address: addr,
								Image:   filepath.Base(i.Name),
								String:  s,
							})
						}
					}
				}
			}
		}
	}

	return strs, nil
}

// GetWebkitVersion returns the WebKit version from a dyld_shared_cache file
func GetWebkitVersion(f *dyld.File) (string, error) {
	image, err := f.Image("/System/Library/Frameworks/WebKit.framework/WebKit")
	if err != nil {
		return "", fmt.Errorf("image not in DSC: %v", err)
	}

	m, err := image.GetPartialMacho()
	if err != nil {
		return "", fmt.Errorf("failed to create MachO for image %s: %v", image.Name, err)
	}

	return m.SourceVersion().Version.String(), nil
}

func GetUserAgent(f *dyld.File, sysVer *plist.SystemVersion) (string, error) {
	// NOTES:
	// This calls WebCore::standardUserAgentWithApplicationName (which has iOS and Maco variants)
	//    - which reads the SystemVersion.plist to get the OS version and replaces `.` with `_`
	// Which is called by MobileSafari.app via
	//    -[WKWebViewConfiguration setApplicationNameForUserAgent:_SFApplicationNameForUserAgent()];
	//	      - `_SFApplicationNameForUserAgent` is in the MobileSafari framework
	//        - which reads the Safari version from it's SFClass bundle aka it's Info.plist `CFBundleShortVersion` string key
	//        - and uses that in the fmt string `"Version/%@ Mobile/15E148 Safari/604.1"` which gets used as the `applicationName` in the `standardUserAgentWithApplicationName` func
	// The last piece of the puzzle is it get's the device name from _isClassic or MGCopyAnswer("DeviceName")
	// It then uses all that info to build the string:
	// makeString("Mozilla/5.0 (", deviceNameForUserAgent(), "; CPU ", osNameForUserAgent(), " ", osVersion, " like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)", separator, applicationName);
	//
	// image, err := f.Image("WebKit")
	// if err != nil {
	// 	return "", fmt.Errorf("image not in DSC: %v", err)
	// }

	// m, err := image.GetPartialMacho()
	// if err != nil {
	// 	return "", fmt.Errorf("failed to create MachO for image %s: %v", image.Name, err)
	// }
	return "", nil
}

func OpenFromIPSW(ipswPath, pemDB string, driverKit, all bool) (*mount.Context, []*dyld.File, error) {
	ctx, err := mount.DmgInIPSW(ipswPath, "sys", pemDB)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to mount IPSW: %v", err)
	}

	dscs, err := dyld.GetDscPathsInMount(ctx.MountPoint, driverKit, all)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get DSC paths in %s: %v", ctx.MountPoint, err)
	}
	if len(dscs) == 0 {
		return nil, nil, fmt.Errorf("no DSCs found in IPSW mount %s", ctx.MountPoint)
	}

	var fs []*dyld.File
	for _, dsc := range dscs {
		if len(filepath.Ext(dsc)) == 0 {
			f, err := dyld.Open(dsc)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to open DSC: %v", err)
			}
			fs = append(fs, f)
		}
	}

	return ctx, fs, nil
}

func GetTBD(f *dyld.File, dylib string, generic bool) (string, error) {
	image, err := f.Image(dylib)
	if err != nil {
		return "", fmt.Errorf("image not in DSC: %v", err)
	}

	m, err := image.GetMacho()
	if err != nil {
		return "", fmt.Errorf("failed to get macho from image: %v", err)
	}
	defer m.Close()

	var reexports []string
	if rexps := m.GetLoadsByName("LC_REEXPORT_DYLIB"); len(rexps) > 0 {
		for _, rexp := range rexps {
			reexports = append(reexports, rexp.(*macho.ReExportDylib).Name)
		}
	}

	t, err := tbd.NewTBD(image, reexports, generic)
	if err != nil {
		return "", fmt.Errorf("failed to create tbd file for %s: %v", dylib, err)
	}

	outTBD, err := t.Generate()
	if err != nil {
		return "", fmt.Errorf("failed to create tbd file for %s: %v", dylib, err)
	}

	if rexps := m.GetLoadsByName("LC_REEXPORT_DYLIB"); len(rexps) > 0 {
		for _, rexp := range rexps {
			image, err := f.Image(rexp.(*macho.ReExportDylib).Name)
			if err != nil {
				return "", fmt.Errorf("image not in DSC: %v", err)
			}
			t, err := tbd.NewTBD(image, nil, generic)
			if err != nil {
				return "", fmt.Errorf("failed to create tbd file for %s: %v", dylib, err)
			}

			rexpOut, err := t.Generate()
			if err != nil {
				return "", fmt.Errorf("failed to create tbd file for %s: %v", dylib, err)
			}
			outTBD += rexpOut
		}
	}

	outTBD += "...\n"

	return outTBD, nil
}
