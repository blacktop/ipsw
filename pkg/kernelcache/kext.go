package kernelcache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-arm64"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/fixupchains"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
)

const tagPtrMask = 0xffff000000000000

type PrelinkInfo struct {
	PrelinkInfoDictionary []CFBundle `plist:"_PrelinkInfoDictionary,omitempty"`
}

type CFBundle struct {
	ID   string `plist:"CFBundleIdentifier,omitempty"`
	Name string `plist:"CFBundleName,omitempty"`

	SDK                 string   `plist:"DTSDKName,omitempty"`
	SDKBuild            string   `plist:"DTSDKBuild,omitempty"`
	Xcode               string   `plist:"DTXcode,omitempty"`
	XcodeBuild          string   `plist:"DTXcodeBuild,omitempty"`
	Copyright           string   `plist:"NSHumanReadableCopyright,omitempty"`
	BuildMachineOSBuild string   `plist:"BuildMachineOSBuild,omitempty"`
	DevelopmentRegion   string   `plist:"CFBundleDevelopmentRegion,omitempty"`
	PlatformName        string   `plist:"DTPlatformName,omitempty"`
	PlatformVersion     string   `plist:"DTPlatformVersion,omitempty"`
	PlatformBuild       string   `plist:"DTPlatformBuild,omitempty"`
	PackageType         string   `plist:"CFBundlePackageType,omitempty"`
	Version             string   `plist:"CFBundleVersion,omitempty"`
	ShortVersionString  string   `plist:"CFBundleShortVersionString,omitempty"`
	CompatibleVersion   string   `plist:"OSBundleCompatibleVersion,omitempty"`
	MinimumOSVersion    string   `plist:"MinimumOSVersion,omitempty"`
	SupportedPlatforms  []string `plist:"CFBundleSupportedPlatforms,omitempty"`
	Signature           string   `plist:"CFBundleSignature,omitempty"`

	IOKitPersonalities map[string]interface{} `plist:"IOKitPersonalities,omitempty"`
	OSBundleLibraries  map[string]string      `plist:"OSBundleLibraries,omitempty"`
	UIDeviceFamily     []int                  `plist:"UIDeviceFamily,omitempty"`

	OSBundleRequired             string   `plist:"OSBundleRequired,omitempty"`
	UIRequiredDeviceCapabilities []string `plist:"UIRequiredDeviceCapabilities,omitempty"`

	AppleSecurityExtension bool `plist:"AppleSecurityExtension,omitempty"`

	InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion,omitempty"`
	OSKernelResource      bool   `plist:"OSKernelResource,omitempty"`
	GetInfoString         string `plist:"CFBundleGetInfoString,omitempty"`
	AllowUserLoad         bool   `plist:"OSBundleAllowUserLoad,omitempty"`
	ExecutableLoadAddr    uint64 `plist:"_PrelinkExecutableLoadAddr,omitempty"`

	ModuleIndex  uint64 `plist:"ModuleIndex,omitempty"`
	Executable   string `plist:"CFBundleExecutable,omitempty"`
	BundlePath   string `plist:"_PrelinkBundlePath,omitempty"`
	RelativePath string `plist:"_PrelinkExecutableRelativePath,omitempty"`
}

type KmodInfoT struct {
	NextAddr          uint64
	InfoVersion       int32
	ID                uint32
	Name              [64]byte
	Version           [64]byte
	ReferenceCount    int32  // # linkage refs to this
	ReferenceListAddr uint64 // who this refs (links on)
	Address           uint64 // starting address
	Size              uint64 // total size
	HeaderSize        uint64 // unwired hdr size
	StartAddr         uint64
	StopAddr          uint64
}

func (i KmodInfoT) String() string {
	return fmt.Sprintf("id: %#x, name: %s, version: %s, ref_cnt: %d, ref_list: %#x, addr: %#x, size: %#x, header_size: %#x, start: %#x, stop: %#x, next: %#x, info_ver: %d",
		i.ID,
		string(i.Name[:]),
		string(i.Version[:]),
		i.ReferenceCount,
		i.ReferenceListAddr,
		i.Address,
		i.Size,
		i.HeaderSize,
		i.StartAddr,
		i.StopAddr,
		i.NextAddr,
		i.InfoVersion,
	)
}

func getKextStartVMAddrs(m *macho.File) ([]uint64, error) {
	if kmodStart := m.Section("__PRELINK_INFO", "__kmod_start"); kmodStart != nil {
		data, err := kmodStart.Data()
		if err != nil {
			return nil, err
		}
		ptrs := make([]uint64, kmodStart.Size/8)
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
			return nil, err
		}
		return ptrs, nil
	}
	return nil, fmt.Errorf("section __PRELINK_INFO.__kmod_start not found")
}

func getKextInfos(m *macho.File) ([]KmodInfoT, error) {
	var infos []KmodInfoT
	if kmodStart := m.Section("__PRELINK_INFO", "__kmod_info"); kmodStart != nil {
		data, err := kmodStart.Data()
		if err != nil {
			return nil, err
		}
		ptrs := make([]uint64, kmodStart.Size/8)
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
			return nil, err
		}
		for _, ptr := range ptrs {
			// fmt.Printf("ptr: %#x, untagged: %#x\n", ptr, unTag(ptr))
			off, err := m.GetOffset(ptr | tagPtrMask)
			if err != nil {
				return nil, err
			}
			info := KmodInfoT{}
			infoBytes := make([]byte, binary.Size(info))
			_, err = m.ReadAt(infoBytes, int64(off))
			if err != nil {
				return nil, err
			}

			if err := binary.Read(bytes.NewReader(infoBytes), binary.LittleEndian, &info); err != nil {
				return nil, fmt.Errorf("failed to read KmodInfoT at %#x: %v", off, err)
			}

			// fixups
			info.StartAddr = fixupchains.DyldChainedPtr64KernelCacheRebase{Pointer: info.StartAddr}.Target() + m.GetBaseAddress()
			info.StopAddr = fixupchains.DyldChainedPtr64KernelCacheRebase{Pointer: info.StopAddr}.Target() + m.GetBaseAddress()

			infos = append(infos, info)
		}
		return infos, nil
	}
	return nil, fmt.Errorf("section __PRELINK_INFO.__kmod_start not found")
}

func findCStringVMaddr(m *macho.File, cstr string) (uint64, error) {
	for _, sec := range m.Sections {

		if sec.Flags.IsCstringLiterals() {
			dat, err := sec.Data()
			if err != nil {
				return 0, fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
			}

			csr := bytes.NewBuffer(dat[:])

			for {
				pos := sec.Addr + uint64(csr.Cap()-csr.Len())

				s, err := csr.ReadString('\x00')

				if err == io.EOF {
					break
				}

				if err != nil {
					return 0, fmt.Errorf("failed to read string: %v", err)
				}

				if len(s) > 0 && strings.EqualFold(strings.Trim(s, "\x00"), cstr) {
					return pos, nil
				}
			}
		}
	}

	return 0, fmt.Errorf("string not found in MachO")
}

func GetSandboxOpts(m *macho.File) ([]string, error) {
	var bcOpts []string

	if dconst := m.Section("__DATA_CONST", "__const"); dconst != nil {
		data, err := dconst.Data()
		if err != nil {
			return nil, err
		}
		ptrs := make([]uint64, dconst.Size/8)
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &ptrs); err != nil {
			return nil, err
		}
		found := false
		for _, ptr := range ptrs {
			if ptr == 0 {
				continue
			}

			str, err := m.GetCString(ptr | tagPtrMask)
			if err != nil {
				if found {
					break
				}
				continue
			}

			if str == "default" {
				found = true
			}

			if found {
				bcOpts = append(bcOpts, str)
				if getTag(ptr) != 0x17 { // always directly followed by another pointer
					break
				}
			}
		}
	}

	// GetSandboxProfiles(m)

	return bcOpts, nil
}

// TODO: finish this (make it so when I look at it I don't want to 🤮)
func getSandboxData(m *macho.File, r *bytes.Reader, panic string) ([]byte, error) {
	var profiles []byte
	var sandboxKextStartVaddr uint64
	var sandboxKextStartOffset uint64
	var sandboxKextEndVaddr uint64

	panicStrVMAddr, err := findCStringVMaddr(m, panic)
	if err != nil {
		return nil, err
	}
	panicStrOffset, err := m.GetOffset(panicStrVMAddr)
	if err != nil {
		return nil, err
	}
	utils.Indent(log.WithFields(log.Fields{
		"vmaddr": fmt.Sprintf("%#x", panicStrVMAddr),
		"offset": fmt.Sprintf("%#x", panicStrOffset),
	}).Debug, 2)(fmt.Sprintf("Found: %v", panic))

	startAdders, err := getKextStartVMAddrs(m)
	if err != nil {
		return nil, err
	}

	infos, err := getKextInfos(m)
	if err != nil {
		return nil, err
	}

	for idx, info := range infos {
		if strings.Contains(string(info.Name[:]), "sandbox") {
			sandboxKextStartVaddr = startAdders[idx] | tagPtrMask
			sandboxKextEndVaddr = startAdders[idx+1] | tagPtrMask
			sandboxKextStartOffset, err = m.GetOffset(sandboxKextStartVaddr)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	// sandbox, err := macho.NewFile(io.NewSectionReader(r, int64(sandboxKextStartOffset), int64(sandboxKextEndVaddr-sandboxKextStartVaddr)), macho.FileConfig{
	// 	Offset:    int64(sandboxKextStartOffset),
	// 	SrcReader: io.NewSectionReader(r, 0, 1<<63-1),
	// })
	// if err != nil {
	// 	return nil, err
	// }

	// fmt.Println(sandbox.FileTOC.String())

	sbInstrData := make([]byte, sandboxKextEndVaddr-sandboxKextStartVaddr)
	_, err = m.ReadAt(sbInstrData, int64(sandboxKextStartOffset))
	if err != nil {
		return nil, err
	}

	var prevInstruction arm64.Instruction

	references := make(map[uint64]uint64)

	// extract all immediates
	for i := range arm64.Disassemble(bytes.NewReader(sbInstrData), arm64.Options{StartAddress: int64(sandboxKextStartVaddr)}) {

		if i.Error != nil {
			continue
		}

		operation := i.Instruction.Operation().String()

		if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
			if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
				adrpRegister := prevInstruction.Operands()[0].Reg[0]
				adrpImm := prevInstruction.Operands()[1].Immediate
				if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
					adrpImm += operands[1].Immediate
				} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
					adrpImm += operands[2].Immediate
				}
				references[i.Instruction.Address()] = adrpImm
			}
		}
		if operation == "cbnz" {
			if operands := i.Instruction.Operands(); operands != nil {
				for _, operand := range operands {
					if operand.OpClass == arm64.LABEL {
						references[i.Instruction.Address()] = operand.Immediate
					}
				}
			}
		}

		// fmt.Printf("%#08x:  %s\t%-10v%s\n", i.Instruction.Address(), i.Instruction.OpCodes(), i.Instruction.Operation(), i.Instruction.OpStr())
		prevInstruction = *i.Instruction
	}

	var panicXrefVMAddr uint64
	for k, v := range references {
		if v == panicStrVMAddr {
			panicXrefVMAddr = k - 4
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Panic string Xref %#x => %#x", panicXrefVMAddr, v))
			break
		}
	}

	var failXrefVMAddr uint64
	for k, v := range references {
		if v == panicXrefVMAddr {
			failXrefVMAddr = k
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Failure path Xref %#x => %#x", failXrefVMAddr, v))
			break
		}
	}

	var profileVMAddr uint64
	var profileSize uint64

	for i := range arm64.Disassemble(bytes.NewReader(sbInstrData), arm64.Options{StartAddress: int64(sandboxKextStartVaddr)}) {

		if i.Error != nil {
			continue
		}

		operation := i.Instruction.Operation().String()

		// TODO: identify basic blocks so I could only disass the block that contains the Xref
		if failXrefVMAddr-0x20 < i.Instruction.Address() && i.Instruction.Address() < failXrefVMAddr {
			if (operation == "ldr" || operation == "add") && prevInstruction.Operation().String() == "adrp" {
				if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
					adrpRegister := prevInstruction.Operands()[0].Reg[0]
					adrpImm := prevInstruction.Operands()[1].Immediate
					if operation == "ldr" && adrpRegister == operands[1].Reg[0] {
						adrpImm += operands[1].Immediate
					} else if operation == "add" && adrpRegister == operands[1].Reg[0] {
						adrpImm += operands[2].Immediate
					}
					profileVMAddr = adrpImm
				}
			} else if operation == "mov" {
				if operands := i.Instruction.Operands(); operands != nil {
					for _, operand := range operands {
						if operand.OpClass == arm64.IMM64 {
							profileSize = operand.Immediate
						}
					}
				}
			} else if operation == "movk" && prevInstruction.Operation().String() == "mov" {
				if operands := i.Instruction.Operands(); operands != nil && prevInstruction.Operands() != nil {
					movRegister := prevInstruction.Operands()[0].Reg[0]
					movImm := prevInstruction.Operands()[1].Immediate
					if movRegister == operands[0].Reg[0] {
						if operands[1].OpClass == arm64.IMM32 && operands[1].ShiftType == arm64.SHIFT_LSL {
							profileSize = movImm + (operands[1].Immediate << uint64(operands[1].ShiftValue))
						}
					}
				}
			}
		}

		prevInstruction = *i.Instruction
	}

	utils.Indent(log.WithFields(log.Fields{
		"vmaddr": fmt.Sprintf("%#x", profileVMAddr),
		"size":   fmt.Sprintf("%#x", profileSize),
	}).Info, 2)("Located data")

	profileOffset, err := m.GetOffset(profileVMAddr)
	if err != nil {
		return nil, err
	}

	profiles = make([]byte, profileSize)
	_, err = m.ReadAt(profiles, int64(profileOffset))
	if err != nil {
		return nil, err
	}

	return profiles, nil
}

func GetSandboxProfiles(m *macho.File, r *bytes.Reader) ([]byte, error) {
	log.Info("Searching for sandbox profile data")
	return getSandboxData(m, r, "\"failed to initialize platform sandbox\"")
}

func GetSandboxCollections(m *macho.File, r *bytes.Reader) ([]byte, error) {
	log.Info("Searching for sandbox collection data")
	return getSandboxData(m, r, "\"failed to initialize collection\"")
}

func getTag(ptr uint64) uint64 {
	return ptr >> 48
}

func unTag(ptr uint64) uint64 {
	return (ptr & ((1 << 48) - 1)) | (0xffff << 48)
}

// KextList lists all the kernel extensions in the kernelcache
func KextList(kernel string) error {

	m, err := macho.Open(kernel)
	if err != nil {
		return err
	}
	defer m.Close()

	kextStartAdddrs, err := getKextStartVMAddrs(m)
	if err != nil {
		return err
	}

	if infoSec := m.Section("__PRELINK_INFO", "__info"); infoSec != nil {

		data, err := infoSec.Data()
		if err != nil {
			return err
		}

		var prelink PrelinkInfo
		decoder := plist.NewDecoder(bytes.NewReader(bytes.Trim([]byte(data), "\x00")))
		err = decoder.Decode(&prelink)
		if err != nil {
			return err
		}

		fmt.Println("FOUND:", len(prelink.PrelinkInfoDictionary))
		for _, bundle := range prelink.PrelinkInfoDictionary {
			if !bundle.OSKernelResource {
				fmt.Printf("%#x: %s (%s)\n", kextStartAdddrs[bundle.ModuleIndex]|tagPtrMask, bundle.ID, bundle.Version)
			} else {
				fmt.Printf("%#x: %s (%s)\n", 0, bundle.ID, bundle.Version)
			}
		}
	}

	return nil
}
