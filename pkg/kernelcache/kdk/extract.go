package kdk

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/google/uuid"
)

// Package kdk recreates a Kernel Debug Kit from an MH_FILESET kernelcache: the
// kernel and every KEXT as standalone Mach-Os that kmutil can link again, with their
// Info.plists, codeless KEXTs and the kernel's pseudo-extensions.
//
// The kernel collection builder resolves all references between the images and
// removes their chained fixups and split-segment info. For every image, Extract
// recovers its references (pointers from the collection's fixups, ADRP/ADD/LDR
// pairs, branches, deltas) and hands them to go-macho's File.Export, which
// rebuilds the image like ld64 would.

// Config configures Extract.
type Config struct {
	// Output is the directory the KDK is written to.
	Output string
	// Force overwrites existing files.
	Force bool
	// Symbols are known names of kernelcache addresses (see LoadSymbolMap). They
	// are used for stripped kernelcaches, whose link symbols must be synthesized.
	Symbols map[uint64][]string
}

// Extract writes the KDK of the fileset kernelcache kc to cfg.Output.
func Extract(kc *macho.File, cfg Config) error {
	if kc.FileTOC.FileHeader.Type != types.MH_FILESET {
		return fmt.Errorf("kernelcache type is not MH_FILESET")
	}
	folder := cfg.Output

	var dcf *fixupchains.DyldChainedFixups
	if kc.HasFixups() {
		var err error
		dcf, err = kc.DyldChainedFixups()
		if err != nil {
			return fmt.Errorf("failed to parse fixups from in memory MachO: %v", err)
		}
	}
	baseAddress := kc.GetBaseAddress()

	prelinkInfo, err := parsePrelinkInfo(kc)
	if err != nil {
		return err
	}

	log.Info("Extracting all KEXTs...")
	kernelFolder, extensionFolder, err := createKDKStructure(folder, kc, *prelinkInfo)
	if err != nil {
		return err
	}

	// Parse every entry and recover its references up front: a stripped
	// collection needs all of them to invent consistent symbol names.
	entries := make(map[string]*macho.File)
	for _, fse := range kc.FileSets() {
		mfse, err := openKext(kc, fse)
		if err != nil {
			return fmt.Errorf("failed to parse KEXT %s: %v", fse.EntryID, err)
		}
		entries[fse.EntryID] = mfse
	}

	// build a name→symbol map of all defined symbols across all fileset
	// entries for resolving imported symbols in extracted KEXTs
	kcSymMap := make(map[string]macho.Symbol)
	log.Info("Building kernelcache symbol map...")
	for _, fse := range kc.FileSets() {
		mfse := entries[fse.EntryID]
		if mfse.Symtab != nil {
			for _, sym := range mfse.Symtab.Syms {
				if sym.Type.IsExternalSym() && !sym.Type.IsUndefinedSym() && sym.Value != 0 {
					kcSymMap[sym.Name] = sym
				}
			}
		}
	}
	log.Infof("Built kernelcache symbol map (%d defined symbols)", len(kcSymMap))

	log.Info("Recovering references")
	fixups, err := sortFixups(kc, entries)
	if err != nil {
		return err
	}
	rc := &recovery{
		branchTargets: collectBranchTargets(entries),
		foreign:       newForeignCodeContext(kc, entries),
	}
	references := make(map[string][]*types.SplitInfoEntry)
	for _, fse := range kc.FileSets() {
		refs, err := rc.recoverSplitSegmentReferences(entries[fse.EntryID], fixups[fse.EntryID])
		if err != nil {
			return fmt.Errorf("failed to recover the references of %s: %w", fse.EntryID, err)
		}
		references[fse.EntryID] = refs
	}
	var synthesized *linkSymbols
	if isStrippedCollection(entries) {
		log.Warn("Kernelcache is stripped: synthesizing symbol names for cross-image references")
		if synthesized, err = synthesizeLinkSymbols(entries, references, prelinkInfo.InfoDictionary, cfg.Symbols); err != nil {
			return err
		}
	}

	for _, fse := range kc.FileSets() {
		log.Infof("Extracting %s", fse.EntryID)
		// The kernel keeps its link address, KEXTs are linked at zero.
		entryBase := uint64(0)
		var info bundleInfo
		var fname, plistPath string
		if fse.EntryID == kernelID {
			entryBase = baseAddress
			fname = filepath.Join(kernelFolder, "kernel")
		} else {
			info, err = extractKextInfo(prelinkInfo.InfoDictionary, fse.EntryID)
			if err != nil {
				return fmt.Errorf("failed to extract KEXT info: %v", err)
			}
			// Recreate the bundle where the collection was built from
			// (kmutil records these paths in the new collection).
			if _, plistPath, fname, err = kextBundleLayout(extensionFolder, fse.EntryID, info); err != nil {
				return err
			}
		}

		if _, err := os.Stat(fname); err == nil && !cfg.Force {
			utils.Indent(log.Warn, 2)(fmt.Sprintf("KEXT already exists: %s (use --force to overwrite)", fname))
			continue
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat %s: %w", fname, err)
		}
		mfse := entries[fse.EntryID]
		syms := resolveImports(mfse, kcSymMap)
		if synthesized != nil {
			syms = append(syms, synthesized.exports[fse.EntryID]...)
			syms = append(syms, synthesized.imports[fse.EntryID]...)
		}
		if err := os.MkdirAll(filepath.Dir(fname), 0o755); err != nil {
			return fmt.Errorf("failed to create %s: %w", filepath.Dir(fname), err)
		}
		if fse.EntryID == kernelID {
			if err := fixUnixThreadAddress(mfse, kc); err != nil {
				return err
			}
		}
		exportOpts := []macho.ExportOption{macho.WithReferences(references[fse.EntryID])}
		if synthesized != nil {
			exportOpts = append(exportOpts, macho.WithAddressOnlyBinds())
		}
		if err := mfse.Export(fname, dcf, entryBase, syms, exportOpts...); err != nil {
			return fmt.Errorf("failed to export KEXT %s: %v", fse.EntryID, err)
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", fname))

		if info != nil {
			data, err := serializeKextInfo(standaloneKextInfo(info))
			if err != nil {
				return fmt.Errorf("failed to serialize KEXT info: %v", err)
			}

			if err := os.WriteFile(plistPath, data, 0644); err != nil {
				return fmt.Errorf("failed to write %s: %w", plistPath, err)
			}
			utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", plistPath))
		}
	}

	// Codeless KEXTs (e.g. personality-only bundles) have no fileset
	// entry but are part of the collection through their Info.plist.
	for _, info := range prelinkInfo.InfoDictionary {
		if _, hasExecutable := info["_PrelinkExecutableRelativePath"]; hasExecutable {
			continue
		}
		bundleID, _ := info["CFBundleIdentifier"].(string)
		if bundleID == "" {
			utils.Indent(log.Warn, 2)("Skipping a codeless KEXT without CFBundleIdentifier")
			continue
		}
		_, plistPath, _, err := kextBundleLayout(extensionFolder, bundleID, info)
		if err != nil {
			return err
		}
		if _, err := os.Stat(plistPath); err == nil && !cfg.Force {
			continue
		}
		data, err := serializeKextInfo(standaloneKextInfo(info))
		if err != nil {
			return fmt.Errorf("failed to serialize KEXT info: %v", err)
		}
		if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(plistPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", plistPath, err)
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", plistPath))
	}
	return writePseudoExtensions(extensionFolder, entries[kernelID], prelinkInfo.InfoDictionary)
}

// resolveImports resolves a KEXT's undefined symbols against the parent
// kernelcache's symbol table, returning them as defined symbols suitable
// for injection into the KEXT's own symbol table during export.
func resolveImports(kext *macho.File, kcSymMap map[string]macho.Symbol) []macho.Symbol {
	if kext.Symtab == nil || kcSymMap == nil {
		return nil
	}
	var resolved []macho.Symbol
	for _, sym := range kext.Symtab.Syms {
		if sym.Type.IsUndefinedSym() && sym.Name != "" {
			if kcSym, ok := kcSymMap[sym.Name]; ok {
				resolved = append(resolved, macho.Symbol{
					Name:  sym.Name,
					Type:  types.N_ABS | types.N_EXT,
					Sect:  0,
					Desc:  sym.Desc,
					Value: kcSym.Value,
				})
			}
		}
	}
	return resolved
}

// openKext opens a fileset entry. go-macho's opener returns the first entry
// whose ID ends with the given one, so the entry is moved to the front first.
func openKext(m *macho.File, entry *macho.FilesetEntry) (*macho.File, error) {
	first, selected := -1, -1
	for i, load := range m.Loads {
		if _, ok := load.(*macho.FilesetEntry); ok && first == -1 {
			first = i
		}
		if load == entry {
			selected = i
		}
	}
	if selected == -1 {
		return nil, fmt.Errorf("KEXT %q is not in this kernelcache", entry.EntryID)
	}
	m.Loads[first], m.Loads[selected] = m.Loads[selected], m.Loads[first]
	defer func() { m.Loads[first], m.Loads[selected] = m.Loads[selected], m.Loads[first] }()
	return m.GetFileSetFileByName(entry.EntryID)
}

const kernelID = "com.apple.kernel"

// bundleInfo is a KEXT's Info.plist. It is kept untyped, as all keys must
// survive.
type bundleInfo map[string]any

type prelinkInfoPlist struct {
	InfoDictionary []bundleInfo `plist:"_PrelinkInfoDictionary,omitempty"`
}

// createKDKStructure creates KDK_<version>_<build>.kdk with its
// SystemVersion.plist and returns its Kernels and Extensions folders. The
// version comes from the DT keys of the first KEXT.
func createKDKStructure(folder string, m *macho.File, prelinkInfo prelinkInfoPlist) (string, string, error) {
	kernelFolder := folder
	extensionFolder := folder
	var version, build, platform string
	for _, fse := range m.FileSets() {
		if fse.EntryID != kernelID {
			info, err := extractKextInfo(prelinkInfo.InfoDictionary, fse.EntryID)
			if err != nil {
				log.Warnf("Not creating a KDK layout: %v", err)
				return kernelFolder, extensionFolder, nil
			}
			var versionOk, buildOk, platformOk bool
			version, versionOk = info["DTPlatformVersion"].(string)
			build, buildOk = info["DTPlatformBuild"].(string)
			platform, platformOk = info["DTPlatformName"].(string)
			if !versionOk || !buildOk || !platformOk {
				log.Warnf("Not creating a KDK layout: %s has no DTPlatformVersion, DTPlatformBuild or DTPlatformName", fse.EntryID)
				break
			}

			kdkDirName := "KDK_" + version + "_" + build + ".kdk"
			folder = filepath.Join(folder, kdkDirName)
			folder = filepath.Join(folder, "System/Library")
			kernelFolder = filepath.Join(folder, "Kernels")
			extensionFolder = filepath.Join(folder, "Extensions")
			break
		}
	}

	coreServicesSystemVersionPath := filepath.Join(folder, "CoreServices/SystemVersion.plist")
	systemInfo := make(map[string]string)
	// A stable BuildID: the same kernelcache yields the same KDK.
	identity := build + version
	if id := m.UUID(); id != nil {
		identity = id.String()
	}
	systemInfo["BuildID"] = uuid.NewSHA1(uuid.NameSpaceOID, []byte(identity)).String()
	systemInfo["ProductBuildVersion"] = build
	systemInfo["ProductUserVisibleVersion"] = version
	systemInfo["ProductVersion"] = version
	switch platform {
	case "macosx":
		systemInfo["ProductName"] = "macOS"
	case "iphoneos":
		systemInfo["ProductName"] = "iPhoneOS"
	case "watchos":
		systemInfo["ProductName"] = "Watch OS"
	case "appletvos":
		systemInfo["ProductName"] = "Apple TVOS"
	case "xros":
		systemInfo["ProductName"] = "xrOS"
	}

	var buf bytes.Buffer
	encoder := plist.NewEncoder(&buf)
	encoder.Indent("\x09")
	if err := encoder.Encode(systemInfo); err != nil {
		return "", "", fmt.Errorf("failed to encode SystemVersion.plist: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(coreServicesSystemVersionPath), os.ModePerm); err != nil {
		return "", "", fmt.Errorf("failed to create %s: %w", filepath.Dir(coreServicesSystemVersionPath), err)
	}
	if err := os.WriteFile(coreServicesSystemVersionPath, buf.Bytes(), 0644); err != nil {
		return "", "", fmt.Errorf("failed to write %s: %w", coreServicesSystemVersionPath, err)
	}
	utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", coreServicesSystemVersionPath))

	return kernelFolder, extensionFolder, nil
}

// fixUnixThreadAddress restores the kernel's entry point: the collection
// builder invalidates the kernel's LC_UNIXTHREAD, but the kernelcache header
// carries a valid one.
func fixUnixThreadAddress(kernel *macho.File, kc *macho.File) error {
	kernelcacheLoads := kc.GetLoadsByName("LC_UNIXTHREAD")
	kernelLoads := kernel.GetLoadsByName("LC_UNIXTHREAD")
	if len(kernelcacheLoads) != 1 || len(kernelLoads) != 1 {
		return fmt.Errorf("expected one LC_UNIXTHREAD in the kernelcache and the kernel, found %d and %d", len(kernelcacheLoads), len(kernelLoads))
	}

	// Replace in place: kmutil keeps the kernel's load command order.
	for i, load := range kernel.Loads {
		if load == kernelLoads[0] {
			kernel.Loads[i] = kernelcacheLoads[0]
		}
	}
	return nil
}

func parsePrelinkInfo(m *macho.File) (*prelinkInfoPlist, error) {
	if seg := m.Segment("__PRELINK_INFO"); seg != nil {
		addr := seg.Addr
		size := seg.Filesz
		off, err := m.GetOffset(addr)
		if err != nil {
			return nil, err
		}
		dat := make([]byte, size)
		if _, err := m.ReadAt(dat, int64(off)); err != nil {
			return nil, err
		}

		var prelinkInfo prelinkInfoPlist
		if err := plist.NewDecoder(bytes.NewReader(dat)).Decode(&prelinkInfo); err != nil {
			return nil, err
		}
		return &prelinkInfo, nil
	} else {
		return nil, fmt.Errorf("failed to find segment '__PRELINK_INFO'")
	}
}

func extractKextInfo(infoDictionary []bundleInfo, identifier string) (bundleInfo, error) {
	for _, info := range infoDictionary {
		bundleIdentifier, ok := info["CFBundleIdentifier"].(string)
		if !ok {
			return nil, fmt.Errorf("prelink info has a KEXT without CFBundleIdentifier")
		}
		if bundleIdentifier == identifier {
			return info, nil
		}
	}
	return nil, fmt.Errorf("failed to find info for kext: %s", identifier)
}

// kextBundleLayout returns the bundle directory, Info.plist path and
// executable path of a prelinked KEXT below extensionFolder, following the
// bundle path and executable path the collection recorded (macOS bundles use
// Contents/, others are flat).
func kextBundleLayout(extensionFolder, bundleID string, info bundleInfo) (string, string, string, error) {
	const extensionsPrefix = "/System/Library/Extensions/"
	rel := bundleID + ".kext"
	if bundlePath, ok := info["_PrelinkBundlePath"].(string); ok && strings.HasPrefix(bundlePath, extensionsPrefix) {
		rel = strings.TrimPrefix(bundlePath, extensionsPrefix)
	}
	// The paths come from the kernelcache: keep them inside the KDK.
	bundle, err := utils.SanitizeArchivePath(extensionFolder, filepath.FromSlash(rel))
	if err != nil {
		return "", "", "", fmt.Errorf("invalid bundle path of %s: %w", bundleID, err)
	}

	executableRel, _ := info["_PrelinkExecutableRelativePath"].(string)
	contents := strings.HasPrefix(executableRel, "Contents/")
	if executableRel == "" {
		contents = kextTargetsMacOS(info)
		if executable, ok := info["CFBundleExecutable"].(string); ok && executable != "" {
			executableRel = executable
			if contents {
				executableRel = "Contents/MacOS/" + executable
			}
		}
	}
	plist := filepath.Join(bundle, "Info.plist")
	if contents {
		plist = filepath.Join(bundle, "Contents", "Info.plist")
	}
	executable := ""
	if executableRel != "" {
		if executable, err = utils.SanitizeArchivePath(bundle, filepath.FromSlash(executableRel)); err != nil {
			return "", "", "", fmt.Errorf("invalid executable path of %s: %w", bundleID, err)
		}
	}
	return bundle, plist, executable, nil
}

func kextTargetsMacOS(info bundleInfo) bool {
	if name, ok := info["DTPlatformName"].(string); ok {
		return name == "macosx"
	}
	if platforms, ok := info["CFBundleSupportedPlatforms"].([]any); ok {
		for _, platform := range platforms {
			if platform == "MacOSX" {
				return true
			}
		}
	}
	return false
}

// standaloneKextInfo returns a copy of a prelinked Info.plist without the
// keys the collection builder adds while linking (the original KEXT does not
// carry them, and stale values would describe the old collection).
func standaloneKextInfo(info bundleInfo) bundleInfo {
	result := make(bundleInfo, len(info))
	for key, value := range info {
		switch {
		case strings.HasPrefix(key, "_Prelink"),
			key == "_InfoPlistDigest",
			key == "OSBundleUUID",
			key == "CFBundleNumericVersion":
			continue
		}
		result[key] = value
	}
	return result
}

func serializeKextInfo(info bundleInfo) ([]byte, error) {
	var buf bytes.Buffer
	encoder := plist.NewEncoder(&buf)
	encoder.Indent("\x09")
	if err := encoder.Encode(info); err != nil {
		return nil, fmt.Errorf("failed to encode kextInfo as plist: %w", err)
	}
	return buf.Bytes(), nil
}
