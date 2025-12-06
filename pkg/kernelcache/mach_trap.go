package kernelcache

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/pkg/disass"
)

const (
	MACH_TRAP_TABLE_COUNT = 128
	unknownTrap           = "<unknown>"
	kernInvalidFunc       = "kern_invalid"
	kernelInvalidString   = "kern_invalid mach trap"
)

//go:embed data/syscalls.gz
var syscallsData []byte

type machTrapT struct {
	ArgCount    uint8
	U32Words    uint8
	ReturnsPort uint8
	Padding     [5]uint8
	Function    uint64
	ArgMunge32  uint64
}

// MachTrap is the mach_trap object
type MachTrap struct {
	Number int
	Name   string
	Args   []string
	machTrapT
}

// MachSyscall is the mach tral object
type MachSyscall struct {
	Arguments []string `json:"arguments"`
	Name      string   `json:"name"`
	Number    int      `json:"number"`
}

// BsdSyscall is the bsd syscall object
type BsdSyscall struct {
	Arguments []string `json:"arguments"`
	Name      string   `json:"name"`
	Number    int      `json:"number"`
	Old       bool     `json:"old,omitempty"`
}

// SyscallsData is the struct that holds the syscall data
type SyscallsData struct {
	MachSyscalls []MachSyscall `json:"mach_syscalls"`
	BsdSyscalls  []BsdSyscall  `json:"bsd_syscalls"`
}

// GetMachSyscallByNumber returns the mach trap for the given number
func (s SyscallsData) GetMachSyscallByNumber(num int) (MachSyscall, error) {
	for _, sc := range s.MachSyscalls {
		if sc.Number == num {
			return sc, nil
		}
	}
	return MachSyscall{}, fmt.Errorf("mach trap %d not found", num)
}

func (s SyscallsData) GetBsdSyscallByNumber(num int) (BsdSyscall, error) {
	for _, sc := range s.BsdSyscalls {
		if sc.Number == num {
			if sc.Old {
				sc.Name = "nosys"
			}
			return sc, nil
		}
	}
	return BsdSyscall{}, fmt.Errorf("mach trap %d not found", num)
}

var colorAddr = colors.Faint().SprintfFunc()
var colorBold = colors.Bold().SprintFunc()
var colorField = colors.BoldHiCyan().SprintFunc()
var colorName = colors.BoldHiBlue().SprintFunc()
var colorType = colors.BoldHiYellow().SprintFunc()
var colorSubSystem = colors.BoldHiMagenta().SprintFunc()

func (m MachTrap) String() string {
	var funcStr string
	if m.Name != kernInvalidFunc && m.Name != unknownTrap {
		var args []string
		for _, arg := range m.Args {
			parts := strings.Split(arg, " ")
			if len(parts) == 2 {
				args = append(args, fmt.Sprintf("%s %s", colorType(parts[0]), (parts[1])))
			} else {
				args = append(args, colorType(arg))
			}
		}
		funcStr = fmt.Sprintf("%s(%s);", colorName(m.Name), strings.Join(args, ", "))
	} else {
		if m.Name == kernInvalidFunc {
			return fmt.Sprintf("%s: %s", colorAddr("%#x", m.Function), colorAddr(m.Name))
		}
		return fmt.Sprintf("%s: %s", colorAddr("%#x", m.Function), colorBold(m.Name))
	}
	return fmt.Sprintf("%s: %s\t%s=%#x\t%s=%d\t%s=%d\t%s",
		colorAddr("%#x", m.Function),
		colorBold(m.Name),
		colorField("munge"), m.ArgMunge32,
		colorField("nargs"), m.ArgCount,
		colorField("ret_port"), m.ReturnsPort,
		funcStr)
}

func getSyscallsData() (*SyscallsData, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(syscallsData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()
	var scdata SyscallsData
	if err := json.NewDecoder(gzr).Decode(&scdata); err != nil {
		return nil, fmt.Errorf("failed to decode syscall data; %v", err)
	}
	return &scdata, nil
}

func getStringAddress(m *macho.File) (uint64, error) {
	if sec := m.Section("__TEXT", "__cstring"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return 0, err
		}

		if found := bytes.Index(dat, []byte(kernelInvalidString)); found > 0 {
			return sec.Addr + uint64(found), nil
		}
	}
	return 0, fmt.Errorf("failed to find kern_invalid mach trap string")
}

func getKernelInvalidAddress(m *macho.File) (uint64, error) {
	strAddr, err := getStringAddress(m)
	if err != nil {
		return 0, err
	}

	data, err := m.Section("__TEXT_EXEC", "__text").Data()
	if err != nil {
		return 0, err
	}

	engine := disass.NewMachoDisass(m, &disass.Config{
		Data:         data,
		StartAddress: m.Section("__TEXT_EXEC", "__text").Addr,
	})

	if err := engine.Triage(); err != nil {
		return 0, fmt.Errorf("first pass triage failed: %v", err)
	}

	if ok, loc := engine.Contains(strAddr); ok {
		kernelInvalid, err := m.GetFunctionForVMAddr(loc)
		if err != nil {
			return 0, err
		}
		return kernelInvalid.StartAddr, nil
	}

	return 0, fmt.Errorf("failed to find kern_invalid mach trap address")
}

func patternMatch(m *macho.File) (uint64, error) {
	if sec := m.Section("__DATA_CONST", "__const"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return 0, err
		}

		r := bytes.NewReader(dat)

		var zero uint64
		var kernelInvalid uint64
		var match uint64
		for {
			if err := binary.Read(r, binary.LittleEndian, &zero); err != nil {
				return 0, err
			}
			if zero != 0 {
				continue
			}
			if err := binary.Read(r, binary.LittleEndian, &kernelInvalid); err != nil {
				return 0, err
			}
			if kernelInvalid == 0 {
				continue
			}
			if err := binary.Read(r, binary.LittleEndian, &zero); err != nil {
				return 0, err
			}
			if zero != 0 {
				continue
			}
			if err := binary.Read(r, binary.LittleEndian, &zero); err != nil {
				return 0, err
			}
			if zero != 0 {
				continue
			}
			if err := binary.Read(r, binary.LittleEndian, &match); err != nil {
				return 0, err
			}
			if match == kernelInvalid {
				break
			}
		}

		return m.SlidePointer(kernelInvalid), nil
	}

	return 0, fmt.Errorf("failed to find __DATA_CONST __const section in kernel")
}

// GetMachTrapTable returns the mach trap table for the given kernel.
func GetMachTrapTable(m *macho.File) ([]MachTrap, error) {
	syscalls, err := getSyscallsData()
	if err != nil {
		return nil, err
	}

	var mtraps []MachTrap

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		var err error
		m, err = m.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return nil, fmt.Errorf("failed to parse fileset entry com.apple.kernel; %v", err)
		}
	}

	kernelInvalidAddr, err := patternMatch(m) // fast way
	if err != nil {
		log.Warn("failed to find mach trap table using pattern match, falling back to slower emulation method")
		kernelInvalidAddr, err = getKernelInvalidAddress(m)
		if err != nil {
			return nil, err
		}
	}

	kernelInvalidBytePattern := make([]byte, 8)
	binary.LittleEndian.PutUint64(kernelInvalidBytePattern, kernelInvalidAddr)

	if sec := m.Section("__DATA_CONST", "__const"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, err
		}

		r := bytes.NewReader(dat)

		var match uint64
		for {
			if err := binary.Read(r, binary.LittleEndian, &match); err != nil {
				return nil, err
			}
			if m.SlidePointer(match) == kernelInvalidAddr {
				break
			}
		}

		r.Seek(-8*2, io.SeekCurrent) // rewind

		curr, _ := r.Seek(0, io.SeekCurrent)

		log.WithField("mach_trap_table", fmt.Sprintf("%#x", uint64(curr)+sec.Addr)).Infof("Found")

		mtrapts := make([]machTrapT, MACH_TRAP_TABLE_COUNT)
		if err := binary.Read(r, binary.LittleEndian, mtrapts); err != nil {
			return nil, err
		}

		// TODO: after the mach_trap_table are the 'mach_trap_names' array (in macOS or non stripped kernels) we should parse to get NEW trap names etc

		for i := range mtrapts {
			mtrapts[i].Function = m.SlidePointer(mtrapts[i].Function)
			mtrapts[i].ArgMunge32 = m.SlidePointer(mtrapts[i].ArgMunge32)
			mtrap, err := syscalls.GetMachSyscallByNumber(i)
			if err != nil {
				if mtrapts[i].Function == kernelInvalidAddr {
					mtrap = MachSyscall{
						Number: i,
						Name:   kernInvalidFunc,
					}
				} else {
					mtrap = MachSyscall{
						Number: i,
						Name:   unknownTrap,
					}
				}
			}
			mtraps = append(mtraps, MachTrap{
				Number:    mtrap.Number,
				Name:      mtrap.Name,
				Args:      mtrap.Arguments,
				machTrapT: mtrapts[i],
			})
		}

		return mtraps, nil
	}

	return nil, fmt.Errorf("failed to find __DATA_CONST __const section in kernel")
}
