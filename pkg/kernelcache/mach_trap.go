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

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/fatih/color"
)

const (
	numMachTraps        = 128
	kernInvalidFunc     = "kern_invalid"
	kernelInvalidString = "kern_invalid mach trap"
)

//go:embed data/syscalls.gz
var syscallsData []byte

type machTrapT struct {
	Function    uint64
	ArgMunge32  uint64
	ArgCount    uint8
	U32Words    uint8
	ReturnsPort uint8
	Padding     [5]uint8
}

type MachTrap struct {
	Number int
	Name   string
	Args   []string
	machTrapT
}

type MachSyscall struct {
	Arguments []string `json:"arguments"`
	Name      string   `json:"name"`
	Number    int      `json:"number"`
}
type BsdSyscall struct {
	Arguments []string `json:"arguments"`
	Name      string   `json:"name"`
	Number    int      `json:"number"`
	Old       bool     `json:"old,omitempty"`
}
type SyscallsData struct {
	MachSyscalls []MachSyscall `json:"mach_syscalls"`
	BsdSyscalls  []BsdSyscall  `json:"bsd_syscalls"`
}

func (s SyscallsData) GetMachSyscallByNumber(num int) (MachSyscall, error) {
	for _, sc := range s.MachSyscalls {
		if sc.Number == num {
			return sc, nil
		}
	}
	return MachSyscall{}, fmt.Errorf("mach trap %d not found", num)
}

var colorAddr = color.New(color.Faint).SprintfFunc()
var colorField = color.New(color.Bold, color.FgHiCyan).SprintFunc()
var colorName = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorType = color.New(color.Bold, color.FgHiYellow).SprintFunc()

func (m MachTrap) String() string {
	var funcStr string
	if m.Name != kernInvalidFunc {
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
	}
	return fmt.Sprintf("%s: %s\t%s=%#x\t%s=%d\t%s=%d\t%s",
		colorAddr("%#x", m.Function),
		m.Name,
		colorField("munge"), m.ArgMunge32,
		colorField("args"), m.ArgCount,
		colorField("return_port"), m.ReturnsPort,
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

	symbolMap := make(map[uint64]string)

	data, err := m.Section("__TEXT_EXEC", "__text").Data()
	if err != nil {
		return 0, err
	}

	engine := disass.NewMachoDisass(m, &symbolMap, &disass.Config{
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

func patternMatch(m *macho.File) ([]MachTrap, error) {
	syscalls, err := getSyscallsData()
	if err != nil {
		return nil, err
	}

	var mtraps []MachTrap

	if sec := m.Section("__DATA_CONST", "__const"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, err
		}

		r := bytes.NewReader(dat)

		var zero uint64
		var nonzero uint64
		var match uint64
		for {
			if err := binary.Read(r, binary.LittleEndian, &nonzero); err != nil {
				return nil, err
			}
			if nonzero == 0 {
				continue
			}
			if err := binary.Read(r, binary.LittleEndian, &zero); err != nil {
				return nil, err
			}
			if zero != 0 {
				continue
			}
			if err := binary.Read(r, binary.LittleEndian, &zero); err != nil {
				return nil, err
			}
			if zero != 0 {
				continue
			}
			if err := binary.Read(r, binary.LittleEndian, &match); err != nil {
				return nil, err
			}
			if nonzero == match {
				r.Seek(-8, io.SeekCurrent) // rewind
				break
			}
		}

		mtrapts := make([]machTrapT, numMachTraps)
		if err := binary.Read(r, binary.LittleEndian, mtrapts); err != nil {
			return nil, err
		}

		for i := 0; i < len(mtrapts); i++ {
			mtrapts[i].Function = m.SlidePointer(mtrapts[i].Function)
			if mtrapts[i].Function == 0 {
				break
			}
			mtrapts[i].ArgMunge32 = m.SlidePointer(mtrapts[i].ArgMunge32)
			mtrap, err := syscalls.GetMachSyscallByNumber(i + 1)
			if err != nil {
				mtrap = MachSyscall{
					Number: i + 1,
					Name:   kernInvalidFunc,
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

	mtraps, err = patternMatch(m) // fast way
	if err == nil {
		return mtraps, nil
	}

	ptr, err := m.GetPointerAtAddress(0xFFFFFFF0078E6138)
	if err != nil {
		return nil, err
	}
	fmt.Printf("ptr: %#x\n", ptr)

	ptr, err = m.GetPointerAtAddress(0xFFFFFFF0078E6140)
	if err != nil {
		return nil, err
	}
	fmt.Printf("ptr: %#x\n", ptr)

	kernelInvalidAddr, err := getKernelInvalidAddress(m)
	if err != nil {
		return nil, err
	}

	kernelInvalidBytePattern := make([]byte, 8)
	binary.LittleEndian.PutUint64(kernelInvalidBytePattern, kernelInvalidAddr)

	if sec := m.Section("__DATA_CONST", "__const"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, err
		}

		r := bytes.NewReader(dat)
		off := int64(0)
		var match uint64
		for {
			if err := binary.Read(r, binary.LittleEndian, &match); err != nil {
				return nil, err
			}
			if m.SlidePointer(match) == kernelInvalidAddr {
				break
			}
			off += 8
		}

		r.Seek(off, io.SeekStart)

		mtrapts := make([]machTrapT, numMachTraps)
		if err := binary.Read(r, binary.LittleEndian, mtrapts); err != nil {
			return nil, err
		}

		for i := 0; i < len(mtrapts); i++ {
			mtrapts[i].Function = m.SlidePointer(mtrapts[i].Function)
			mtrapts[i].ArgMunge32 = m.SlidePointer(mtrapts[i].ArgMunge32)
			mtrap, err := syscalls.GetMachSyscallByNumber(i + 1)
			if err != nil {
				mtrap = MachSyscall{
					Number: i + 1,
					Name:   kernInvalidFunc,
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
