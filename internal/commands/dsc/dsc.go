// Package dsc implements the `dsc` commands
package dsc

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/blacktop/go-macho/pkg/codesign"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// Dylib is a struct that contains information about a dyld_shared_cache dylib
type Dylib struct {
	Index       int    `json:"index,omitempty"`
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	LoadAddress uint64 `json:"load_address,omitempty"`
}

// Info is a struct that contains information about a dyld_shared_cache file
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

// String is a struct that contains information about a dyld_shared_cache string
type String struct {
	Address uint64 `json:"address,omitempty"`
	Image   string `json:"image,omitempty"`
	String  string `json:"string,omitempty"`
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

// GetStrings returns a list of strings from a dyld_shared_cache file for a given regex pattern
func GetStrings(f *dyld.File, pattern string) ([]String, error) {
	var strs []String

	if len(pattern) == 0 {
		return nil, fmt.Errorf("pattern cannot be empty")
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
	}

	return strs, nil
}
