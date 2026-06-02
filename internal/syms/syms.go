package syms

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/signature"
)

const (
	highestBitMask uint64 = ^uint64(1 << 63)
	isKernelMask   uint64 = 1 << 62
)

// scanImage is a single Mach-O image surfaced while scanning an IPSW, paired
// with the extra metadata the streaming JSONL emitter needs but the persisted
// model does not carry (arch/cpu, parent DSC/kernelcache identity).
//
// Macho is normalized exactly as the daemon database stores it, so the symbol
// start/end values are byte-identical whether they are persisted or streamed.
type scanImage struct {
	Macho             *model.Macho // nil for a "dsc" container event
	Kind              string       // "dsc", "dylib", "kext", "kernel", or "macho"
	CPU               string       // lowercase arch slice, e.g. "arm64e"
	Arch              string       // lowercase arch slice, e.g. "arm64e"
	DSCUUID           string       // parent DSC UUID ("dsc" + "dylib")
	SharedRegionStart uint64       // parent DSC shared region start ("dsc")
	KernelUUID        string       // parent kernelcache UUID ("kext")
	KernelVersion     string       // kernelcache version ("kernel")
}

// scanVisitor is invoked once per image (and once per DSC container) as an IPSW
// is walked. Returning an error aborts the scan.
type scanVisitor func(*scanImage) error

// dbAccumulator is a scanVisitor that rebuilds the nested model graph the daemon
// database persists, preserving the exact structure the previous Scan produced.
type dbAccumulator struct {
	ipsw *model.Ipsw
	dscs map[string]*model.DyldSharedCache
	kcs  map[string]*model.Kernelcache
}

func newDBAccumulator(ipsw *model.Ipsw) *dbAccumulator {
	return &dbAccumulator{
		ipsw: ipsw,
		dscs: make(map[string]*model.DyldSharedCache),
		kcs:  make(map[string]*model.Kernelcache),
	}
}

func (a *dbAccumulator) visit(img *scanImage) error {
	switch img.Kind {
	case "dsc":
		if _, ok := a.dscs[img.DSCUUID]; !ok {
			cache := &model.DyldSharedCache{UUID: img.DSCUUID, SharedRegionStart: img.SharedRegionStart}
			a.dscs[img.DSCUUID] = cache
			a.ipsw.DSCs = append(a.ipsw.DSCs, cache)
		}
	case "dylib":
		cache, ok := a.dscs[img.DSCUUID]
		if !ok {
			return fmt.Errorf("dylib %s references unknown DSC %s", img.Macho.UUID, img.DSCUUID)
		}
		cache.Images = append(cache.Images, img.Macho)
	case "kernel":
		kc, ok := a.kcs[img.Macho.UUID]
		if !ok {
			kc = &model.Kernelcache{UUID: img.Macho.UUID, Version: img.KernelVersion}
			a.kcs[img.Macho.UUID] = kc
			a.ipsw.Kernels = append(a.ipsw.Kernels, kc)
		}
		// A non-fileset kernel is both the cache container and its only kext.
		if len(img.Macho.Symbols) > 0 {
			kc.Kexts = append(kc.Kexts, img.Macho)
		}
	case "kext":
		kc, ok := a.kcs[img.KernelUUID]
		if !ok {
			return fmt.Errorf("kext %s references unknown kernelcache %s", img.Macho.UUID, img.KernelUUID)
		}
		kc.Kexts = append(kc.Kexts, img.Macho)
	case "macho":
		a.ipsw.FileSystem = append(a.ipsw.FileSystem, img.Macho)
	default:
		return fmt.Errorf("unknown scan image kind: %q", img.Kind)
	}
	return nil
}

func appendModelSymbol(dst *[]*model.Symbol, seen map[uint64]struct{}, addr, end uint64, name string) {
	if name == "" || addr == 0 {
		return
	}
	if _, ok := seen[addr]; ok {
		return
	}
	if end <= addr {
		// Keep data symbols as exact-address matches for the existing
		// start <= addr < end lookup contract used by the symbol DB.
		end = addr + 1
	}
	*dst = append(*dst, &model.Symbol{
		Name:  model.Name{Name: name},
		Start: addr & highestBitMask,
		End:   end & highestBitMask,
	})
	seen[addr] = struct{}{}
}

func appendExtraKernelSymbols(dst *[]*model.Symbol, m *macho.File, smap signature.SymbolMap, seen map[uint64]struct{}) {
	if m == nil || len(smap) == 0 {
		return
	}

	addrs := make([]uint64, 0, len(smap))
	for addr := range smap {
		if _, ok := seen[addr]; ok {
			continue
		}
		if m.FindSegmentForVMAddr(addr) == nil {
			continue
		}
		addrs = append(addrs, addr)
	}
	slices.Sort(addrs)

	for _, addr := range addrs {
		appendModelSymbol(dst, seen, addr, addr+1, smap[addr])
	}
}

func kernelFunctionSymbolName(m *macho.File, fn types.Function, smap signature.SymbolMap) string {
	if syms, err := m.FindAddressSymbols(fn.StartAddr); err == nil {
		// Preserve the historical behavior of keeping the last symbol
		// returned for a shared address.
		var name string
		for _, sym := range syms {
			name = sym.Name
		}
		if name != "" {
			return name
		}
	}
	if sym, ok := smap[fn.StartAddr]; ok {
		return sym
	}
	return fmt.Sprintf("func_%x", fn.StartAddr)
}

func kernelFunctionSymbol(m *macho.File, fn types.Function, smap signature.SymbolMap) *model.Symbol {
	return &model.Symbol{
		Name:  model.Name{Name: kernelFunctionSymbolName(m, fn, smap)},
		Start: fn.StartAddr & highestBitMask,
		End:   fn.EndAddr & highestBitMask,
	}
}

func collectKernelMachoSymbols(m *macho.File, smap signature.SymbolMap) []*model.Symbol {
	funcs := m.GetFunctions()
	symbols := make([]*model.Symbol, 0, len(funcs))
	seen := make(map[uint64]struct{}, len(funcs))

	for _, fn := range funcs {
		symbols = append(symbols, kernelFunctionSymbol(m, fn, smap))
		seen[fn.StartAddr] = struct{}{}
	}

	appendExtraKernelSymbols(&symbols, m, smap, seen)

	return symbols
}

// machoArch returns the lowercase architecture slice (e.g. "arm64e") for a
// Mach-O, matching the short form used elsewhere in the CLI.
func machoArch(m *macho.File) string {
	return strings.ToLower(m.SubCPU.String(m.CPU))
}

// scanKernels extracts every kernelcache from the IPSW and visits the cache
// container plus each of its KEXTs. Kernel and KEXT symbol addresses are
// bit-63-cleared (highestBitMask) exactly as the daemon database stores them.
func scanKernels(ipswPath, sigDir string, visit scanVisitor) error {
	var sigs []signature.Symbolicator

	if sigDir != "" {
		var err error
		sigs, err = signature.Parse(sigDir)
		if err != nil {
			return fmt.Errorf("failed to parse signatures: %v", err)
		}
	}

	out, err := extract.Kernelcache(&extract.Config{
		IPSW:   ipswPath,
		Output: os.TempDir(),
	})
	if err != nil {
		return fmt.Errorf("failed to extract kernelcache: %w", err)
	}
	defer func() {
		for k := range out {
			os.Remove(k)
		}
	}()
	for k := range out {
		smap := signature.NewSymbolMap()
		if err := smap.Symbolicate(k, sigs, true); err != nil {
			return fmt.Errorf("failed to symbolicate kernelcache: %v", err)
		}

		m, err := macho.Open(k)
		if err != nil {
			return fmt.Errorf("failed to open kernel: %w", err)
		}
		defer m.Close()
		kv, err := kernelcache.GetVersion(m)
		if err != nil {
			return err
		}
		arch := machoArch(m)
		container := &model.Macho{
			UUID: m.UUID().String(),
			Path: model.Path{Path: filepath.Base(k)},
		}
		if text := m.Segment("__TEXT"); text != nil {
			container.TextStart = text.Addr & highestBitMask
			container.TextEnd = (text.Addr + text.Filesz) & highestBitMask
		}
		if m.FileTOC.FileHeader.Type == types.MH_FILESET {
			if err := visit(&scanImage{
				Macho:         container,
				Kind:          "kernel",
				CPU:           arch,
				Arch:          arch,
				KernelVersion: kv.String(),
			}); err != nil {
				return err
			}
			for idx, fe := range m.FileSets() {
				log.WithFields(log.Fields{
					"index": idx,
					"name":  fe.EntryID,
				}).Debug("Parsing Kernel Kext")
				mfe, err := m.GetFileSetFileByName(fe.EntryID)
				if err != nil {
					return fmt.Errorf("failed to parse entry %s: %v", fe.EntryID, err)
				}
				kext := &model.Macho{
					Path: model.Path{Path: fe.EntryID},
					UUID: mfe.UUID().String(),
				}
				if text := mfe.Segment("__TEXT"); text != nil {
					kext.TextStart = text.Addr & highestBitMask
					kext.TextEnd = (text.Addr + text.Filesz) & highestBitMask
				}
				kext.Symbols = collectKernelMachoSymbols(mfe, smap)
				if err := visit(&scanImage{
					Macho:      kext,
					Kind:       "kext",
					CPU:        machoArch(mfe),
					Arch:       machoArch(mfe),
					KernelUUID: m.UUID().String(),
				}); err != nil {
					return err
				}
			}
		} else {
			container.Symbols = collectKernelMachoSymbols(m, smap)
			if err := visit(&scanImage{
				Macho:         container,
				Kind:          "kernel",
				CPU:           arch,
				Arch:          arch,
				KernelVersion: kv.String(),
			}); err != nil {
				return err
			}
		}
	}

	return nil
}

// scanDSCs opens every dyld_shared_cache in the IPSW and visits a "dsc"
// container (carrying shared_region_start) followed by each of its dylib images.
func scanDSCs(ipswPath, pemDB string, visit scanVisitor) error {
	ctx, fs, err := dsc.OpenFromIPSW(ipswPath, pemDB, false, true)
	if err != nil {
		return fmt.Errorf("failed to open DSC from IPSW: %w", err)
	}
	defer func() {
		for _, f := range fs {
			f.Close()
		}
		ctx.Unmount()
	}()

	for _, f := range fs {
		if err := visit(&scanImage{
			Kind:              "dsc",
			DSCUUID:           f.UUID.String(),
			SharedRegionStart: f.Headers[f.UUID].SharedRegionStart,
		}); err != nil {
			return err
		}

		for idx, img := range f.Images {
			log.WithFields(log.Fields{
				"index": idx,
				"name":  img.Name,
			}).Debug("Parsing DSC Image")
			img.ParsePublicSymbols(false)
			img.ParseLocalSymbols(false)
			m, err := img.GetMacho()
			if err != nil {
				return fmt.Errorf("failed to parse dyld_shared_cache image: %w", err)
			}
			defer m.Close()
			dylib := &model.Macho{
				UUID: m.UUID().String(),
				Path: model.Path{Path: img.Name},
			}
			if text := m.Segment("__TEXT"); text != nil {
				dylib.TextStart = text.Addr
				dylib.TextEnd = text.Addr + text.Filesz
			}
			for _, fn := range m.GetFunctions() {
				var msym *model.Symbol
				if sym, ok := f.AddressToSymbol.Get(fn.StartAddr); ok {
					msym = &model.Symbol{
						Name:  model.Name{Name: sym},
						Start: fn.StartAddr,
						End:   fn.EndAddr,
					}
				} else {
					msym = &model.Symbol{
						Name:  model.Name{Name: fmt.Sprintf("func_%x", fn.StartAddr)},
						Start: fn.StartAddr,
						End:   fn.EndAddr,
					}
				}
				dylib.Symbols = append(dylib.Symbols, msym)
			}
			if err := visit(&scanImage{
				Macho:   dylib,
				Kind:    "dylib",
				CPU:     machoArch(m),
				Arch:    machoArch(m),
				DSCUUID: f.UUID.String(),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// scanFileSystem walks every Mach-O in the IPSW file system and visits it as a
// "macho" image.
func scanFileSystem(ipswPath, pemDB string, visit scanVisitor) error {
	return search.ForEachMachoInIPSW(ipswPath, pemDB, func(path string, m *macho.File) error {
		if m.UUID() == nil {
			return nil
		}
		mm := &model.Macho{
			UUID: m.UUID().String(),
			Path: model.Path{Path: path},
		}
		if text := m.Segment("__TEXT"); text != nil {
			mm.TextStart = text.Addr
			mm.TextEnd = text.Addr + text.Filesz
		}
		for _, fn := range m.GetFunctions() {
			var msym *model.Symbol
			if syms, err := m.FindAddressSymbols(fn.StartAddr); err == nil {
				for _, sym := range syms {
					fn.Name = sym.Name
				}
				msym = &model.Symbol{
					Name:  model.Name{Name: fn.Name},
					Start: fn.StartAddr,
					End:   fn.EndAddr,
				}
			} else {
				msym = &model.Symbol{
					Name:  model.Name{Name: fmt.Sprintf("func_%x", fn.StartAddr)},
					Start: fn.StartAddr,
					End:   fn.EndAddr,
				}
			}
			mm.Symbols = append(mm.Symbols, msym)
		}
		return visit(&scanImage{
			Macho: mm,
			Kind:  "macho",
			CPU:   machoArch(m),
			Arch:  machoArch(m),
		})
	})
}

// Scan scans the IPSW file and extracts information about the kernels, DSCs, and file system.
func Scan(ipswPath, pemDB, sigsDir string, db db.Database) (err error) {
	/* IPSW */
	sha1, err := utils.Sha1(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to calculate sha1: %w", err)
	}
	inf, err := info.Parse(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to parse IPSW info: %w", err)
	}
	ipsw := &model.Ipsw{
		ID:      sha1,
		Name:    filepath.Base(ipswPath),
		BuildID: inf.Plists.BuildManifest.ProductBuildVersion,
		Version: inf.Plists.BuildManifest.ProductVersion,
	}
	if err := db.Create(ipsw); err != nil {
		return fmt.Errorf("failed to create IPSW in database: %w", err)
	}
	for _, dev := range inf.Plists.BuildManifest.SupportedProductTypes {
		ipsw.Devices = append(ipsw.Devices, &model.Device{
			Name: dev,
		})
	}
	if err := db.Save(ipsw); err != nil {
		return fmt.Errorf("failed to save IPSW to database: %w", err)
	}

	acc := newDBAccumulator(ipsw)
	/* KERNEL */
	if err := scanKernels(ipswPath, sigsDir, acc.visit); err != nil {
		return fmt.Errorf("failed to scan kernels: %w", err)
	}
	/* DSC */
	if err := scanDSCs(ipswPath, pemDB, acc.visit); err != nil {
		return fmt.Errorf("failed to scan DSCs: %w", err)
	}
	/* FileSystem */
	if err := scanFileSystem(ipswPath, pemDB, acc.visit); err != nil {
		return fmt.Errorf("failed to search for machos in IPSW: %w", err)
	}

	log.Debug("Saving IPSW with FileSystem")
	return db.Save(ipsw)
}

// Rescan re-scans the IPSW file and extracts information about the kernels, DSCs, and file system.
func Rescan(ipswPath, pemDB, sigsDir string, db db.Database) (err error) {
	/* IPSW */
	sha1, err := utils.Sha1(ipswPath)
	if err != nil {
		return fmt.Errorf("failed to calculate sha1: %w", err)
	}
	ipsw, err := db.Get(sha1)
	if err != nil {
		return fmt.Errorf("failed to get IPSW from database: %w", err)
	}
	// The kernel, DSC, and file system graphs are rebuilt from scratch on
	// rescan; clear them so a re-scan replaces rather than duplicates entries.
	ipsw.Kernels = nil
	ipsw.DSCs = nil
	ipsw.FileSystem = nil
	acc := newDBAccumulator(ipsw)
	/* KERNEL */
	if err := scanKernels(ipswPath, sigsDir, acc.visit); err != nil {
		return fmt.Errorf("failed to scan kernels: %w", err)
	}
	/* DSC */
	if err := scanDSCs(ipswPath, pemDB, acc.visit); err != nil {
		return fmt.Errorf("failed to scan DSCs: %w", err)
	}
	/* FileSystem */
	if err := scanFileSystem(ipswPath, pemDB, acc.visit); err != nil {
		return fmt.Errorf("failed to search for machos in IPSW: %w", err)
	}

	log.Debug("Saving IPSW with FileSystem")
	return db.Save(ipsw)
}

func GetIPSW(version, build, device string, db db.Database) (*model.Ipsw, error) {
	return db.GetIPSW(version, build, device)
}

// GetMachO retrieves the Mach-O file with the given UUID from the database.
func GetMachO(uuid string, db db.Database) (*model.Macho, error) {
	return db.GetMachO(uuid)
}

// GetDSC retrieves the Dyld Shared Cache (DSC) with the given UUID from the database.
func GetDSC(uuid string, db db.Database) (*model.DyldSharedCache, error) {
	return db.GetDSC(uuid)
}

// GetDSCImage retrieves the Mach-O image with the given UUID and address from the
// Dyld Shared Cache (DSC) in the database.
func GetDSCImage(uuid string, addr uint64, db db.Database) (*model.Macho, error) {
	return db.GetDSCImage(uuid, addr)
}

// Get retrieves the symbols associated with the given UUID from the database.
func Get(uuid string, db db.Database) ([]*model.Symbol, error) {
	return db.GetSymbols(uuid)
}

// GetForAddr retrieves the symbol associated with the given UUID and address from the database.
// It returns the symbol and an error if any.
func GetForAddr(uuid string, addr uint64, db db.Database) (*model.Symbol, error) {
	return db.GetSymbol(uuid, addr)
}
