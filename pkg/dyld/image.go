package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"sync"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

var ErrMachOSectionNotFound = errors.New("MachO missing required section")

type rangeEntry struct {
	StartAddr  uint64
	FileOffset uint64
	Size       uint32
}

type patchableExport struct {
	Name           string
	OffsetOfImpl   uint32
	PatchLocations []CachePatchableLocation
}

type astate struct {
	mu sync.Mutex

	Deps        bool
	Got         bool
	Stubs       bool
	StubHelpers bool
	Exports     bool
	Privates    bool
}

func (a *astate) SetDeps(done bool) {
	a.mu.Lock()
	a.Deps = done
	a.mu.Unlock()
}

func (a *astate) IsDepsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Deps
}
func (a *astate) SetGot(done bool) {
	a.mu.Lock()
	a.Got = done
	a.mu.Unlock()
}

func (a *astate) IsGotDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Got
}
func (a *astate) SetStubHelpers(done bool) {
	a.mu.Lock()
	a.StubHelpers = done
	a.mu.Unlock()
}

func (a *astate) IsStubHelpersDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.StubHelpers
}
func (a *astate) SetStubs(done bool) {
	a.mu.Lock()
	a.Stubs = done
	a.mu.Unlock()
}

func (a *astate) IsStubsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Stubs
}
func (a *astate) SetExports(done bool) {
	a.mu.Lock()
	a.Exports = done
	a.mu.Unlock()
}

func (a *astate) IsExportsDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Exports
}
func (a *astate) SetPrivates(done bool) {
	a.mu.Lock()
	a.Privates = done
	a.mu.Unlock()
}

func (a *astate) IsPrivatesDone() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Privates
}

type analysis struct {
	State        astate
	Dependencies []string
	GotPointers  map[uint64]uint64
	SymbolStubs  map[uint64]uint64
}

// CacheImage represents a dyld dylib image.
type CacheImage struct {
	Name         string
	Index        uint32
	Info         CacheImageInfo
	LocalSymbols []*CacheLocalSymbol64
	Mappings     *cacheMappingsWithSlideInfo
	CacheLocalSymbolsEntry
	CacheImageInfoExtra
	CacheImageTextInfo
	Initializer      uint64
	DOFSectionAddr   uint64
	DOFSectionSize   uint32
	SlideInfo        slideInfo
	RangeEntries     []rangeEntry
	PatchableExports []patchableExport
	ObjC             objcInfo

	Analysis analysis

	cache *File // pointer back to the dyld cache that the image belongs to
	cuuid types.UUID
	CacheReader
	m  *macho.File
	pm *macho.File // partial macho
}

// NewCacheReader returns a CacheReader that reads from r
// starting at offset off and stops with EOF after n bytes.
// It also stubs out the MachoReader required SeekToAddr and ReadAtAddr
func NewCacheReader(off int64, n int64, u types.UUID) CacheReader {
	return CacheReader{off, off, off + n, u}
}

// CacheReader implements Read, Seek, and ReadAt on a section
// of an underlying ReaderAt.
type CacheReader struct {
	base  int64
	off   int64
	limit int64
	ruuid types.UUID
}

func (i *CacheImage) Read(p []byte) (n int, err error) {
	if i.off >= i.limit {
		return 0, io.EOF
	}
	if max := i.limit - i.off; int64(len(p)) > max {
		p = p[0:max]
	}
	n, err = i.cache.r[i.ruuid].ReadAt(p, i.off)
	i.off += int64(n)
	return
}

func (i *CacheImage) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	default:
		return 0, fmt.Errorf("Seek: invalid whence")
	case io.SeekStart:
		offset += i.base
	case io.SeekCurrent:
		offset += i.off
	case io.SeekEnd:
		offset += i.limit
	}
	if offset < i.base {
		return 0, fmt.Errorf("Seek: invalid offset")
	}
	i.off = offset
	return offset - i.base, nil
}

func (i *CacheImage) ReadAt(p []byte, off int64) (n int, err error) {
	if i.m == nil {
		i.m, err = i.GetPartialMacho()
		if err != nil {
			return -1, err
		}
	}
	i.ruuid, _, err = i.cache.GetOffset(i.m.Segment("__LINKEDIT").Addr)
	// i.ruuid, offset, err = i.cache.GetOffset(addr)
	if err != nil {
		return -1, err
	}
	if off < 0 || off >= i.limit-i.base {
		return 0, io.EOF
	}
	off += i.base
	if max := i.limit - off; int64(len(p)) > max {
		p = p[0:max]
		n, err = i.cache.r[i.ruuid].ReadAt(p, off)
		if err == nil {
			err = io.EOF
		}
		return n, err
	}
	// fmt.Printf("image.ReadAt: cache_uuid=%s, uuid=%s, off=%#x\n", i.cuuid, uuid, off)
	return i.cache.r[i.ruuid].ReadAt(p, off)
}

func (i *CacheImage) SeekToAddr(addr uint64) error {
	uuid, offset, err := i.cache.GetOffset(addr)
	if err != nil {
		return err
	}
	i.ruuid = uuid
	i.Seek(int64(offset), io.SeekStart)
	return nil
}

// ReadAtAddr reads data at a given virtual address
func (i *CacheImage) ReadAtAddr(buf []byte, addr uint64) (int, error) {
	uuid, off, err := i.cache.GetOffset(addr)
	if err != nil {
		return -1, err
	}
	i.ruuid = uuid
	// fmt.Printf("image.ReadAt: cache_uuid=%s, uuid=%s, off=%#x\n", i.cuuid, uuid, off)
	return i.cache.r[i.ruuid].ReadAt(buf, int64(off))
}

// GetOffset returns the offset for a given virtual address
func (i *CacheImage) GetOffset(address uint64) (uint64, error) {
	u, o, err := i.cache.GetOffset(address)
	if err != nil {
		return 0, err
	}
	i.ruuid = u
	// fmt.Printf("prim_uuid=%s, cache_uuid=%s, uuid=%s, off=%#x\n", i.cache.UUID, i.cuuid, u, o)
	return o, nil
}

// GetVMAddress returns the virtual address for a given offset
func (i *CacheImage) GetVMAddress(offset uint64) (uint64, error) {
	return i.cache.GetVMAddressForUUID(i.cuuid, offset)
}

// GetMacho parses dyld image as a MachO (slow)
func (i *CacheImage) GetMacho() (*macho.File, error) {
	if i.m != nil {
		return i.m, nil
	}

	offset, err := i.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}

	var rsBase uint64
	sec, opt, err := i.cache.getOptimizations()
	if err != nil {
		return nil, err
	}

	if opt.Version == 16 {
		rsBase = sec.Addr + opt.RelativeMethodSelectorBaseAddressCacheOffset
	}

	i.CacheReader = NewCacheReader(0, 1<<63-1, i.cuuid)
	vma := types.VMAddrConverter{
		Converter: func(addr uint64) uint64 {
			return i.cache.SlideInfo.SlidePointer(addr)
		},
		VMAddr2Offet: func(address uint64) (uint64, error) {
			return i.GetOffset(address)
		},
		Offet2VMAddr: func(offset uint64) (uint64, error) {
			return i.GetVMAddress(offset)
		},
	}
	i.m, err = macho.NewFile(io.NewSectionReader(i.cache.r[i.cuuid], int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
		Offset:               int64(offset),
		SectionReader:        types.NewCustomSectionReader(i.cache.r[i.cuuid], &vma, 0, 1<<63-1),
		CacheReader:          i,
		VMAddrConverter:      vma,
		RelativeSelectorBase: rsBase,
	})
	if err != nil {
		return nil, err
	}

	return i.m, nil
}

// GetPartialMacho parses dyld image as a partial MachO (fast)
func (i *CacheImage) GetPartialMacho() (*macho.File, error) {
	if i.pm != nil {
		return i.pm, nil
	}
	offset, err := i.GetOffset(i.LoadAddress)
	if err != nil {
		return nil, err
	}
	vma := types.VMAddrConverter{
		Converter: func(addr uint64) uint64 {
			return i.cache.SlideInfo.SlidePointer(addr)
		},
		VMAddr2Offet: func(address uint64) (uint64, error) {
			return i.GetOffset(address)
		},
		Offet2VMAddr: func(offset uint64) (uint64, error) {
			return i.GetVMAddress(offset)
		},
	}
	i.pm, err = macho.NewFile(io.NewSectionReader(i.cache.r[i.cuuid], int64(offset), int64(i.TextSegmentSize)), macho.FileConfig{
		LoadFilter: []types.LoadCmd{
			types.LC_SEGMENT_64,
			types.LC_DYLD_INFO,
			types.LC_DYLD_INFO_ONLY,
			types.LC_ID_DYLIB,
			types.LC_UUID,
			types.LC_BUILD_VERSION,
			types.LC_SOURCE_VERSION,
			types.LC_SUB_FRAMEWORK,
			types.LC_SUB_CLIENT,
			types.LC_REEXPORT_DYLIB,
			types.LC_LOAD_DYLIB,
			types.LC_LOAD_WEAK_DYLIB,
			types.LC_LOAD_UPWARD_DYLIB},
		Offset:          int64(offset),
		SectionReader:   types.NewCustomSectionReader(i.cache.r[i.cuuid], &vma, 0, 1<<63-1),
		CacheReader:     i,
		VMAddrConverter: vma,
		// RelativeSelectorBase: rsBase,
	})
	if err != nil {
		return nil, err
	}

	return i.pm, nil
}

func (i *CacheImage) GetLocalSymbols() []macho.Symbol {
	var syms []macho.Symbol
	for _, lsym := range i.LocalSymbols {
		syms = append(syms, macho.Symbol{
			Name:  lsym.Name,
			Type:  lsym.Type,
			Sect:  lsym.Sect,
			Desc:  lsym.Desc,
			Value: lsym.Value,
		})
	}
	return syms
}

// Analyze analyzes an image by parsing it's symbols, stubs and GOT
func (i *CacheImage) Analyze() error {

	if err := i.cache.GetAllExportedSymbolsForImage(i, false); err != nil {
		log.Errorf("failed to parse exported symbols for %s", i.Name)
	}

	if err := i.cache.GetLocalSymbolsForImage(i); err != nil {
		if !errors.Is(err, ErrNoLocals) {
			return err
		}
	}

	if !i.cache.IsArm64() {
		utils.Indent(log.Warn, 2)("image analysis of stubs and GOT only works on arm64 architectures")
	}

	if !i.Analysis.State.IsStubHelpersDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s symbol stub helpers", i.Name)
		if err := i.ParseHelpers(); err != nil {
			if !errors.Is(err, ErrMachOSectionNotFound) {
				return err
			}
		}
	}

	if !i.Analysis.State.IsGotDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s global offset table", i.Name)
		if err := i.ParseGOT(); err != nil {
			return err
		}

		for entry, target := range i.Analysis.GotPointers {
			if symName, ok := i.cache.AddressToSymbol[target]; ok {
				i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
			} else {
				if img, err := i.cache.GetImageContainingTextAddr(target); err == nil {
					if err := img.Analyze(); err != nil {
						return err
					}
					if symName, ok := i.cache.AddressToSymbol[target]; ok {
						i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
					} else if laptr, ok := i.Analysis.GotPointers[target]; ok {
						if symName, ok := i.cache.AddressToSymbol[laptr]; ok {
							i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got.%s", symName)
						}
					} else {
						utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for GOT entry %#x => %#x in %s", entry, target, img.Name))
						i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got_%x ; %s", target, filepath.Base(img.Name))
					}
				} else {
					i.cache.AddressToSymbol[entry] = fmt.Sprintf("__got_%x", target)
				}

			}
		}
	}

	if !i.Analysis.State.IsStubsDone() && i.cache.IsArm64() {
		log.Debugf("parsing %s symbol stubs", i.Name)
		if err := i.ParseStubs(); err != nil {
			return err
		}

		for stub, target := range i.Analysis.SymbolStubs {
			if symName, ok := i.cache.AddressToSymbol[target]; ok {
				i.cache.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
			} else {
				img, err := i.cache.GetImageContainingTextAddr(target)
				if err != nil {
					return err
				}
				if err := img.Analyze(); err != nil {
					return err
				}
				if symName, ok := i.cache.AddressToSymbol[target]; ok {
					i.cache.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
				} else if laptr, ok := i.Analysis.GotPointers[target]; ok {
					if symName, ok := i.cache.AddressToSymbol[laptr]; ok {
						i.cache.AddressToSymbol[stub] = fmt.Sprintf("j_%s", symName)
					}
				} else {
					utils.Indent(log.Debug, 2)(fmt.Sprintf("no sym found for stub %#x => %#x in %s", stub, target, img.Name))
					i.cache.AddressToSymbol[stub] = fmt.Sprintf("__stub_%x ; %s", target, filepath.Base(img.Name))
				}
			}
		}
	}

	return nil
}

// ParseGOT parse global offset table in MachO
func (i *CacheImage) ParseGOT() error {

	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}
	defer m.Close()

	i.Analysis.GotPointers = make(map[uint64]uint64)

	if authPtr := m.Section("__AUTH_CONST", "__auth_ptr"); authPtr != nil {
		dat, err := authPtr.Data()
		if err != nil {
			return fmt.Errorf("failed to get %s.%s section data: %v", authPtr.Seg, authPtr.Name, err)
		}

		ptrs := make([]uint64, authPtr.Size/8)
		if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
			return fmt.Errorf("failed to read __AUTH_CONST.__auth_ptr ptrs; %v", err)
		}

		for idx, ptr := range ptrs {
			i.Analysis.GotPointers[authPtr.Addr+uint64(idx*8)] = i.cache.SlideInfo.SlidePointer(ptr)
		}
	}

	for _, sec := range m.Sections {
		if sec.Flags.IsNonLazySymbolPointers() || sec.Flags.IsLazySymbolPointers() { // TODO: make sure this doesn't break things
			dat, err := sec.Data()
			if err != nil {
				return fmt.Errorf("failed to get %s.%s section data: %v", sec.Seg, sec.Name, err)
			}

			ptrs := make([]uint64, sec.Size/8)
			if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &ptrs); err != nil {
				return fmt.Errorf("failed to read %s.%s NonLazySymbol pointers; %v", sec.Seg, sec.Name, err)
			}

			for idx, ptr := range ptrs {
				i.Analysis.GotPointers[sec.Addr+uint64(idx*8)] = i.cache.SlideInfo.SlidePointer(ptr)
			}
		}
	}

	i.Analysis.State.SetGot(true)

	return nil
}

// ParseStubs parse symbol stubs in MachO
func (i *CacheImage) ParseStubs() error {

	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}
	defer m.Close()

	i.Analysis.SymbolStubs = make(map[uint64]uint64)

	for _, sec := range m.Sections {
		if sec.Flags.IsSymbolStubs() {
			var adrpImm uint64
			var adrpAddr uint64
			var instrValue uint32
			var results [1024]byte
			var prevInst *disassemble.Instruction

			dat, err := sec.Data()
			if err != nil {
				return err
			}

			r := bytes.NewReader(dat)

			startAddr := sec.Addr

			for {
				err = binary.Read(r, binary.LittleEndian, &instrValue)

				if err == io.EOF {
					break
				}

				instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
				if err != nil {
					fmt.Printf("%#08x:  %s\t.long\t%#x ; (%s)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue, err.Error())
					break
				}

				if instruction.Operation == disassemble.ARM64_ADD && prevInst.Operation == disassemble.ARM64_ADRP {
					if instruction.Operands != nil && prevInst.Operands != nil {
						// adrp      	x17, #0x1e3be9000
						adrpRegister := prevInst.Operands[0].Registers[0] // x17
						adrpImm = prevInst.Operands[1].Immediate          // #0x1e3be9000
						// add       	x17, x17, #0x1c0
						if adrpRegister == instruction.Operands[0].Registers[0] {
							adrpImm += instruction.Operands[2].Immediate
							adrpAddr = prevInst.Address
						}
					}
				} else if instruction.Operation == disassemble.ARM64_LDR && prevInst.Operation == disassemble.ARM64_ADRP {
					if instruction.Operands != nil && prevInst.Operands != nil {
						// adrp	x16, #0x1e3be9000
						adrpRegister := prevInst.Operands[0].Registers[0] // x16
						adrpImm = prevInst.Operands[1].Immediate          // #0x1e3be9000
						// ldr	x16, [x16, #0x560]
						if adrpRegister == instruction.Operands[0].Registers[0] {
							adrpImm += instruction.Operands[1].Immediate
							adrpAddr = prevInst.Address
							addr, err := i.cache.ReadPointerAtAddress(adrpImm)
							if err != nil {
								return fmt.Errorf("failed to read pointer at %#x: %v", adrpImm, err)
							}
							i.Analysis.SymbolStubs[adrpAddr] = i.cache.SlideInfo.SlidePointer(addr)
						}
					}
				} else if instruction.Operation == disassemble.ARM64_LDR && prevInst.Operation == disassemble.ARM64_ADD {
					// add       	x17, x17, #0x1c0
					addRegister := prevInst.Operands[0].Registers[0] // x17
					// ldr       	x16, [x17]
					if addRegister == instruction.Operands[1].Registers[0] {
						addr, err := i.cache.ReadPointerAtAddress(adrpImm)
						if err != nil {
							return fmt.Errorf("failed to read pointer at %#x: %v", adrpImm, err)
						}
						i.Analysis.SymbolStubs[adrpAddr] = i.cache.SlideInfo.SlidePointer(addr)
					}
				} else if instruction.Operation == disassemble.ARM64_BR && prevInst.Operation == disassemble.ARM64_ADD {
					// add       	x16, x16, #0x828
					addRegister := prevInst.Operands[0].Registers[0] // x16
					// br        	x16
					if addRegister == instruction.Operands[0].Registers[0] {
						i.Analysis.SymbolStubs[adrpAddr] = adrpImm
					}
				}

				prevInst = instruction
				startAddr += uint64(binary.Size(uint32(0)))
			}
		}
	}

	i.Analysis.State.SetStubs(true)

	return nil
}

// ParseHelpers parse symbol stub helpers in MachO
func (i *CacheImage) ParseHelpers() error {
	m, err := i.GetPartialMacho()
	if err != nil {
		return fmt.Errorf("failed to get MachO for image %s; %v", i.Name, err)
	}
	defer m.Close()

	if sec := m.Section("__TEXT", "__stub_helper"); sec != nil {
		var instrValue uint32
		var results [1024]byte

		dat, err := sec.Data()
		if err != nil {
			return err
		}

		r := bytes.NewReader(dat)

		startAddr := sec.Addr
		stubHelperFnStart := sec.Addr

		for {
			err = binary.Read(r, binary.LittleEndian, &instrValue)

			if err == io.EOF {
				break
			}

			instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
			if err != nil {
				fmt.Printf("%#08x:  %s\t.long\t%#x ; (%s)\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instrValue, err.Error())
				break
			}

			if instruction.Encoding == disassemble.ENC_BR_64_BRANCH_REG { // check if branch location is a function
				if instruction.Operation == disassemble.ARM64_BR {
					stubHelperFnStart = instruction.Address + 4
					continue
				}
				if operands := instruction.Operands; operands != nil {
					for _, operand := range operands {
						if operand.Class == disassemble.LABEL {
							if symName, ok := i.cache.AddressToSymbol[operand.Immediate]; ok {
								i.cache.AddressToSymbol[stubHelperFnStart] = fmt.Sprintf("__stub_helper.%s", symName)
							}
						}
					}
				}
			}

			startAddr += uint64(binary.Size(uint32(0)))
		}

		i.Analysis.State.SetStubHelpers(true)

		return nil
	}

	return fmt.Errorf("dylib does NOT contain __TEXT.__stub_helper section: %w", ErrMachOSectionNotFound)
}
