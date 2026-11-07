package kdk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
)

// writePseudoExtensions recreates the kernel's pseudo-extensions without a KDK.
//
// The KPI bundles (com.apple.kpi.*) are part of the prelink info and were
// written as codeless bundles, but their Info.plist names an executable: a
// symbol-only Mach-O whose LC_UUID kmutil reports as OSBundleUUID. Their parent
// System.kext is the com.apple.kernel pseudo-extension.
func writePseudoExtensions(extensionFolder string, kernel *macho.File, infos []bundleInfo) error {
	sets := kernelSymbolSets(kernel)
	kernelVersion := ""
	for _, info := range infos {
		resource, _ := info["OSKernelResource"].(bool)
		executable, _ := info["CFBundleExecutable"].(string)
		if !resource || executable == "" {
			continue
		}
		if _, hasExecutable := info["_PrelinkExecutableRelativePath"]; hasExecutable {
			continue
		}
		id, _ := info["CFBundleIdentifier"].(string)
		if v, ok := info["CFBundleVersion"].(string); ok && kernelVersion == "" {
			kernelVersion = v
		}
		bundle, _, _, err := kextBundleLayout(extensionFolder, id, info)
		if err != nil {
			return err
		}
		path, err := utils.SanitizeArchivePath(bundle, executable)
		if err != nil {
			return fmt.Errorf("invalid executable of %s: %w", id, err)
		}
		var uuid []byte
		if u, ok := info["OSBundleUUID"].([]byte); ok && len(u) == 16 {
			uuid = u
		}
		if err := os.WriteFile(path, pseudoExtensionMachO(uuid, sets[id]), 0o755); err != nil {
			return fmt.Errorf("failed to write %s: %w", path, err)
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", path))
	}
	if kernelVersion == "" {
		return nil
	}
	// System.kext is only synthesized if the collection did not list it.
	system := filepath.Join(extensionFolder, "System.kext", "Info.plist")
	if _, err := os.Stat(system); err == nil {
		return nil
	}
	data, err := serializeKextInfo(bundleInfo{
		"CFBundleDevelopmentRegion":     "English",
		"CFBundleGetInfoString":         "System Resource Pseudoextension, Apple Inc, " + kernelVersion,
		"CFBundleIdentifier":            "com.apple.kernel",
		"CFBundleInfoDictionaryVersion": "6.0",
		"CFBundleName":                  "System Resource Pseudoextension",
		"CFBundlePackageType":           "KEXT",
		"CFBundleShortVersionString":    kernelVersion,
		"CFBundleSignature":             "????",
		"CFBundleVersion":               kernelVersion,
		"OSBundleAllowUserLoad":         true,
		"OSBundleCompatibleVersion":     kernelVersion,
		"OSBundleRequired":              "Root",
		"OSKernelResource":              true,
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(system), 0o755); err != nil {
		return err
	}
	return os.WriteFile(system, data, 0o644)
}

// kernelSymbolSets returns the symbol names each KPI bundle exports according
// to the kernel's __LINKINFO,__symbolsets.
func kernelSymbolSets(kernel *macho.File) map[string][]string {
	result := make(map[string][]string)
	if kernel == nil {
		return result
	}
	sec := kernel.Section("__LINKINFO", "__symbolsets")
	if sec == nil {
		return result
	}
	data, err := sec.Data()
	if err != nil {
		log.Warnf("Failed to read __LINKINFO,__symbolsets: %v", err)
		return result
	}
	var sets symbolSets
	if _, err := plist.Unmarshal(data, &sets); err != nil {
		log.Warnf("Failed to parse __LINKINFO,__symbolsets: %v", err)
		return result
	}
	for _, set := range sets.SymbolsSets {
		for _, sym := range set.Symbols {
			if sym.SymbolName != "" {
				result[set.CFBundleIdentifier] = append(result[set.CFBundleIdentifier], sym.SymbolName)
			}
		}
	}
	return result
}

// pseudoExtensionMachO builds an arm64e MH_KEXT_BUNDLE that only carries a
// symbol table of undefined names and a UUID, like Apple's KPI executables.
func pseudoExtensionMachO(uuid []byte, symbols []string) []byte {
	symbols = append([]string(nil), symbols...)
	sort.Strings(symbols)
	const (
		headerSize   = 32
		segmentSize  = 72
		symtabSize   = 24
		uuidSize     = 24
		linkeditFile = 0x1000
	)
	var strtab bytes.Buffer
	strtab.WriteString(" \x00")
	var nlist bytes.Buffer
	for _, name := range symbols {
		binary.Write(&nlist, binary.LittleEndian, types.Nlist64{
			Nlist: types.Nlist{Name: uint32(strtab.Len()), Type: types.N_UNDF | types.N_EXT},
		})
		strtab.WriteString(name + "\x00")
	}
	for strtab.Len()%8 != 0 {
		strtab.WriteByte(0)
	}
	symoff := uint32(linkeditFile)
	stroff := symoff + uint32(nlist.Len())
	linkeditSize := uint64(nlist.Len() + strtab.Len())

	var b bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&b, le, types.FileHeader{
		Magic: types.Magic64, CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E,
		Type: types.MH_KEXT_BUNDLE, NCommands: 3, SizeCommands: segmentSize + symtabSize + uuidSize,
		Flags: types.HeaderFlag(0x2), // MH_INCRLINK
	})
	var segname [16]byte
	copy(segname[:], "__LINKEDIT")
	binary.Write(&b, le, types.Segment64{
		LoadCmd: types.LC_SEGMENT_64, Len: segmentSize, Name: segname,
		Addr: 0, Memsz: (linkeditSize + 0x3fff) &^ 0x3fff, Offset: linkeditFile, Filesz: linkeditSize,
		Maxprot: 1, Prot: 1, Flag: 0x4,
	})
	binary.Write(&b, le, types.SymtabCmd{
		LoadCmd: types.LC_SYMTAB, Len: symtabSize, Symoff: symoff, Nsyms: uint32(len(symbols)),
		Stroff: stroff, Strsize: uint32(strtab.Len()),
	})
	var u types.UUID
	copy(u[:], uuid)
	binary.Write(&b, le, types.UUIDCmd{LoadCmd: types.LC_UUID, Len: uuidSize, UUID: u})
	b.Write(make([]byte, linkeditFile-b.Len()))
	b.Write(nlist.Bytes())
	b.Write(strtab.Bytes())
	return b.Bytes()
}
