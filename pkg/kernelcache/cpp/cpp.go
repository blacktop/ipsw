package cpp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/arm64-cgo/emulate/core"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

var OSMetaClassFunc uint64 = 0 // Address of OSMetaClass::OSMetaClass function

// ClassMeta represents metadata for a C++ class discovered in the kernelcache
type ClassMeta struct {
	Name        string       // Class name (e.g., "IOService")
	Size        uint32       // Size of class instances in bytes
	MetaPtr     uint64       // Address of the OSMetaClass object for this class
	SuperMeta   uint64       // Address of superclass's meta (0 if none)
	SuperClass  *ClassMeta   // Pointer to parent class (resolved later)
	AllocFunc   uint64       // Address of the alloc function
	VtableAddr  uint64       // Address of the class's vtable
	Methods     []MethodInfo // Virtual methods in the vtable
	DiscoveryPC uint64       // PC where this class was discovered
	Bundle      string       // Bundle/kext this class belongs to
}

// MethodInfo represents a virtual method in a class vtable
type MethodInfo struct {
	Address uint64 // Function address
	Name    string // Method name (if known)
	Index   int    // Position in vtable
}

func parseClassMeta(m *macho.File, startAddr uint64, data []byte) (*ClassMeta, error) {
	emu := emulate.NewEngine()
	if err := emu.SetMemory(startAddr, data); err != nil {
		return nil, fmt.Errorf("failed to set emulation memory: %v", err)
	}
	emu.Configure(&emulate.EngineConfig{
		MaxInstructions: 100,
		MemoryHandler: func(addr uint64, size int) ([]byte, error) {
			data := make([]byte, size)
			_, err := m.ReadAtAddr(data, addr)
			if err != nil {
				return nil, fmt.Errorf("memory read error at %#x: %v", addr, err)
			}
			return data, nil
		},
		StringHandler: func(addr uint64) (string, error) {
			str, err := m.GetCString(addr)
			if err != nil {
				return "", fmt.Errorf("string read error at %#x: %v", addr, err)
			}
			return str, nil
		},
		ShouldHaltPreHandler: func(state core.State, info core.InstructionInfo) bool {
			// OSMetaClass::OSMetaClass(const char *inClassName, const OSMetaClass *inSuperClass,unsigned int inClassSize)
			if strings.EqualFold(info.Mnemonic, "bl") {
				if state.GetX(3) > 0 { // inClassSize set
					if OSMetaClassFunc == 0 {
						// First time seeing the OSMetaClass function
						OSMetaClassFunc = info.Instruction.Operands[0].Immediate
						return true
					} else if OSMetaClassFunc == info.Instruction.Operands[0].Immediate {
						// We've hit the OSMetaClass function again, stop emulation
						return true
					}
				} else {
					return false // skip calls where inClassSize is not set
				}
			}
			return false
		},
		ShouldTakeBranchHandler: func(state core.State, info core.InstructionInfo) bool {
			if strings.EqualFold(info.Mnemonic, "bl") {
				if OSMetaClassFunc != info.Instruction.Operands[0].Immediate {
					return false // skip calls where inClassSize is not set
				}
			}
			return true
		},
	})
	emu.SetPC(startAddr)
	// emu.StopOnError = false
	if err := emu.Run(); err != nil {
		if !errors.Is(err, core.ErrUnmappedMemory) {
			return nil, fmt.Errorf("emulation error: %v", err)
		}
	}
	if emu.GetRegister(1) != 0 {
		name, err := emu.GetState().ReadString(emu.GetRegister(1))
		if err != nil {
			return nil, fmt.Errorf("failed to read class name at %#x: %v", emu.GetRegister(1), err)
		}
		return &ClassMeta{
			Name:      name,
			MetaPtr:   emu.GetRegister(0),
			SuperMeta: emu.GetRegister(2),
			Size:      uint32(emu.GetRegister(3)),
		}, nil
	}
	OSMetaClassFunc = 0 // reset if we didn't find a valid class
	return nil, fmt.Errorf("failed to parse class metadata: no valid class found")
}

// GetClasses analyzes the given Mach-O kernel file and extracts C++ class metadata

func GetClasses(kernel *macho.File) ([]ClassMeta, error) {
	var classes []ClassMeta
	if kernel.FileTOC.FileHeader.Type == types.MH_FILESET {
		for _, fs := range kernel.FileSets() {
			entry, err := kernel.GetFileSetFileByName(fs.EntryID)
			if err != nil {
				return nil, fmt.Errorf("failed to get fileset entry %s: %v", fs.EntryID, err)
			}
			defer entry.Close()

			if modInitSection := entry.Section("__DATA_CONST", "__mod_init_func"); modInitSection != nil {
				ptrs := make([]uint64, modInitSection.Size/8)
				data, err := modInitSection.Data()
				if err != nil {
					return nil, fmt.Errorf("failed to read __mod_init_func section: %v", err)
				}
				if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, ptrs); err != nil {
					return nil, fmt.Errorf("failed to parse __mod_init_func pointers: %v", err)
				}
				for _, addr := range ptrs {
					if addr == 0 {
						continue
					}
					fn, err := entry.GetFunctionForVMAddr(entry.SlidePointer(addr))
					if err != nil {
						fmt.Printf("Warning: failed to get function at %#x: %v\n", addr, err)
						continue
					}
					funcData, err := entry.GetFunctionData(fn)
					if err != nil {
						return nil, fmt.Errorf("failed to get function data at %#x: %v", addr, err)
					}
					class, err := parseClassMeta(kernel, fn.StartAddr, funcData)
					if err != nil {
						// return nil, fmt.Errorf("failed to parse class metadata for init func at %#x: %v", fn.StartAddr, err)
						log.Errorf("failed to parse class metadata for init func at %#x: %v", fn.StartAddr, err)
						continue
					}
					classes = append(classes, *class)
					log.WithField("entry", fs.EntryID).Infof("Discovered class: %s (meta: %#x) in %s", class.Name, class.MetaPtr, fs.EntryID)
				}
			} else {
				log.WithField("entry", fs.EntryID).Warnf("No __mod_init_func section found")
			}
		}
	} else {
		if modInitSection := kernel.Section("__DATA_CONST", "__mod_init_func"); modInitSection != nil {
			ptrs := make([]uint64, modInitSection.Size/8)
			data, err := modInitSection.Data()
			if err != nil {
				return nil, fmt.Errorf("failed to read __mod_init_func section: %v", err)
			}
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, ptrs); err != nil {
				return nil, fmt.Errorf("failed to parse __mod_init_func pointers: %v", err)
			}
			for _, addr := range ptrs {
				if addr == 0 {
					continue
				}
				fn, err := kernel.GetFunctionForVMAddr(addr)
				if err != nil {
					fmt.Printf("Warning: failed to get function at %#x: %v\n", addr, err)
					continue
				}
				funcData, err := kernel.GetFunctionData(fn)
				if err != nil {
					return nil, fmt.Errorf("failed to get function data at %#x: %v", addr, err)
				}
				class, err := parseClassMeta(kernel, fn.StartAddr, funcData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse class metadata: %v", err)
				}
				classes = append(classes, *class)
				log.Infof("Discovered class: %s (meta: %#x)", class.Name, class.MetaPtr)
			}
		} else {
			return nil, fmt.Errorf("no __mod_init_func section found")
		}
	}

	return classes, nil
}
