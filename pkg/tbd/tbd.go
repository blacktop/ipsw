package tbd

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// tbdArch returns the TBD architecture string for a given CPU
// type and subtype (e.g. "arm64e", "x86_64h").
func tbdArch(cpu types.CPU, sub types.CPUSubtype) string {
	sub = sub & types.CpuSubtypeMask
	switch cpu {
	case types.CPUI386:
		return "i386"
	case types.CPUAmd64:
		if sub == types.CPUSubtypeX86_64H {
			return "x86_64h"
		}
		return "x86_64"
	case types.CPUArm:
		switch sub {
		case types.CPUSubtypeArmV7K:
			return "armv7k"
		case types.CPUSubtypeArmV7S:
			return "armv7s"
		default:
			return "armv7"
		}
	case types.CPUArm64:
		if sub == types.CPUSubtypeArm64E {
			return "arm64e"
		}
		return "arm64"
	case types.CPUArm6432:
		return "arm64_32"
	}
	return "unknown"
}

// tbdPlatform returns the TBD platform string for a given
// LC_BUILD_VERSION platform (e.g. "ios", "bridgeos").
// Returns ("", error) for platforms without a known TBD target triple.
func tbdPlatform(p types.Platform) (string, error) {
	switch p {
	case types.Platform_macOS:
		return "macos", nil
	case types.Platform_iOS:
		return "ios", nil
	case types.Platform_tvOS:
		return "tvos", nil
	case types.Platform_watchOS:
		return "watchos", nil
	case types.Platform_bridgeOS:
		return "bridgeos", nil
	case types.Platform_macCatalyst:
		return "maccatalyst", nil
	case types.Platform_iOsSimulator:
		return "ios-simulator", nil
	case types.Platform_tvOsSimulator:
		return "tvos-simulator", nil
	case types.Platform_watchOsSimulator:
		return "watchos-simulator", nil
	case types.Platform_Driverkit:
		return "driverkit", nil
	case types.Platform_visionOS:
		return "xros", nil
	case types.Platform_visionOsSimulator:
		return "xros-simulator", nil
	case types.Platform_Firmware:
		return "firmware", nil
	case types.Platform_sepOS:
		return "sepos", nil
	}
	return "", fmt.Errorf("unsupported TBD platform: %s", p)
}

// TBD object
type TBD struct {
	Targets        []string
	Path           string
	CurrentVersion string
	Umbrella       string
	ReExports      []string
	Symbols        []string
	ObjcClasses    []string
	ObjcIvars      []string
}

// NewTBD creates a new tbd object
func NewTBD(image *dyld.CacheImage, reexports []string, generic bool) (*TBD, error) {
	var targets []string
	var currentVersion string
	var syms []string
	var objcClasses []string
	var objcIvars []string
	var umbrella string

	m, err := image.GetMacho()
	if err != nil {
		return nil, err
	}
	defer m.Close()

	arch := tbdArch(m.CPU, m.SubCPU)

	if generic {
		// Generic TBD: list all arch+platform combinations that could
		// link against this dylib.
		for _, a := range []string{"i386", "x86_64", "x86_64h", "arm64", "arm64e"} {
			for _, p := range []string{"macos", "maccatalyst"} {
				targets = append(targets, a+"-"+p)
			}
		}
		for _, a := range []string{"armv7", "armv7s", "arm64", "arm64e"} {
			targets = append(targets, a+"-ios")
		}
		for _, a := range []string{"i386", "x86_64", "arm64"} {
			targets = append(targets, a+"-ios-simulator")
		}
	} else {
		bvs := m.BuildVersions()
		if len(bvs) > 0 {
			for _, bv := range bvs {
				plat, err := tbdPlatform(bv.Platform)
				if err != nil {
					return nil, fmt.Errorf("TBD generation for %s: %w", image.Name, err)
				}
				targets = append(targets, arch+"-"+plat)
			}
		} else {
			// No LC_BUILD_VERSION — derive platform from LC_VERSION_MIN_* load commands
			for _, l := range m.Loads {
				switch l.(type) {
				case *macho.VersionMinMacOSX:
					targets = append(targets, arch+"-macos")
				case *macho.VersionMiniPhoneOS:
					targets = append(targets, arch+"-ios")
				case *macho.VersionMinTvOS:
					targets = append(targets, arch+"-tvos")
				case *macho.VersionMinWatchOS:
					targets = append(targets, arch+"-watchos")
				}
			}
			if len(targets) == 0 {
				targets = append(targets, arch+"-macos")
			}
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("unable to determine TBD targets for %s (cpu=%s, build versions=%v)", image.Name, m.CPU, bvs)
		}
	}

	// get current version
	if id := m.DylibID(); id != nil {
		currentVersion = id.CurrentVersion.String()
	}

	// get umbrella
	for _, l := range m.Loads {
		if s, ok := l.(*macho.SubFramework); ok {
			umbrella = s.String()
			break
		}
	}

	// get public symbols
	for _, sym := range m.Symtab.Syms {
		if sym.Name == "<redacted>" || sym.Value == 0 {
			continue
		}
		if sym.Type.IsExternalSym() {
			syms = utils.UniqueAppend(syms, sym.Name)
		}
	}
	if exports, err := m.DyldExports(); err == nil {
		for _, export := range exports {
			syms = utils.UniqueAppend(syms, export.Name)
		}
	}
	if exports, err := m.GetExports(); err == nil {
		for _, export := range exports {
			syms = utils.UniqueAppend(syms, export.Name)
		}
	}

	// get objc classes and ivars
	if m.HasObjC() {
		classes, err := m.GetObjCClasses()
		if err != nil {
			return nil, err
		}
		for _, class := range classes {
			objcClasses = append(objcClasses, class.Name)
			for _, ivar := range class.Ivars {
				objcIvars = append(objcIvars, fmt.Sprintf("%s.%s", class.Name, ivar.Name))
			}
		}
	}

	sort.Strings(syms)
	sort.Strings(objcClasses)
	sort.Strings(objcIvars)

	return &TBD{
		Targets:        targets,
		Path:           image.Name,
		CurrentVersion: currentVersion,
		Umbrella:       umbrella,
		ReExports:      reexports,
		Symbols:        syms,
		ObjcClasses:    objcClasses,
		ObjcIvars:      objcIvars,
	}, nil
}

// Generate generates a tbd file from a template
func (t *TBD) Generate() (string, error) {
	var tplOut bytes.Buffer

	tmpl := template.Must(template.New("tbd").Funcs(template.FuncMap{"StringsJoin": strings.Join}).Parse(tbdTemplate))

	if err := tmpl.Execute(&tplOut, t); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return tplOut.String(), nil
}
