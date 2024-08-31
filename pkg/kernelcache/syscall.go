package kernelcache

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/download"
)

//go:embed data/syscall.gz
var syscallData []byte

const (
	// SYS_MAXSYSCALL    = 557
	syscall1Pattern   = "00000000000000000100000000000000"
	syscall2Pattern   = "0000000001000400"
	syscallHeader     = "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include/sys/syscall.h"
	syscallBetaHeader = "/Applications/Xcode-beta.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/include/sys/syscall.h"
)

type returnType int32

const (
	RET_NONE     returnType = 0
	RET_INT_T    returnType = 1
	RET_UINT_T   returnType = 2
	RET_OFF_T    returnType = 3
	RET_ADDR_T   returnType = 4
	RET_SIZE_T   returnType = 5
	RET_SSIZE_T  returnType = 6
	RET_UINT64_T returnType = 7
)

func (r returnType) String() string {
	switch r {
	case RET_NONE:
		return "void"
	case RET_INT_T:
		return "int"
	case RET_UINT_T:
		return "uint"
	case RET_OFF_T:
		return "off_t"
	case RET_ADDR_T:
		return "addr_t"
	case RET_SIZE_T:
		return "size_t"
	case RET_SSIZE_T:
		return "ssize_t"
	case RET_UINT64_T:
		return "uint64_t"
	default:
		return "unknown"
	}
}

type SyscallData struct {
	Names map[int]string
	Table map[int]sysMaster
}

type sysMaster struct {
	Audit       string `json:"audit,omitempty"`
	Files       string `json:"files,omitempty"`
	NameAndArgs string `json:"name_and_args,omitempty"`
}

type sysent struct {
	Call       uint64     `json:"call,omitempty"`        // implementing function
	Munge      uint64     `json:"munge,omitempty"`       // system call arguments munger for 32-bit process
	ReturnType returnType `json:"return_type,omitempty"` // system call return types
	NArg       int16      `json:"n_arg,omitempty"`       // number of args
	ArgBytes   uint16     `json:"arg_bytes,omitempty"`   // Total size of arguments in bytes for 32-bit system calls
}

type Sysent struct {
	Number int      `json:"number,omitempty"`
	Name   string   `json:"name,omitempty"`
	DBName string   `json:"old_name,omitempty"`
	Args   []string `json:"args,omitempty"`
	Proto  string   `json:"proto,omitempty"`
	New    bool     `json:"new,omitempty"`
	Old    bool     `json:"old,omitempty"`
	sysent
}

func (s Sysent) String() string {
	var args []string
	var funcStr string
	var extra string

	if s.Name == "syscall" {
		extra = colorAddr(" // indirect syscall")
	}
	if s.Old {
		s.Name = "nosys"
		extra = colorAddr(fmt.Sprintf(" // old '%s'", s.DBName))
	}

	// get args
	if len(s.Args) == 0 || (len(s.Args) == 1 && s.Args[0] == RET_NONE.String()) {
		args = append(args, "void")
	} else {
		for _, arg := range s.Args {
			parts := strings.Split(arg, " ")
			if len(parts) == 2 {
				args = append(args, fmt.Sprintf("%s %s", colorType(parts[0]), (parts[1])))
			} else {
				args = append(args, colorType(arg))
			}
		}
	}

	funcStr = fmt.Sprintf("%s %s(%s);%s", colorType(s.ReturnType.String()), colorName(s.Name), strings.Join(args, ", "), extra)

	var isNew string
	if s.New && s.Name != "nosys" && s.Name != "enosys" && s.Name != "syscall" {
		isNew = colorBold(" << 👀 [found NEW syscall] 👀 >>")
	}

	if s.Name == "nosys" || s.Name == "enosys" || s.Name == "syscall" {
		s.Name = colorAddr(s.Name)
	} else {
		s.Name = colorBold(s.Name)
	}

	return fmt.Sprintf(
		"%d\t%s: %s\t%s=%#x\t%s=%s\t%s=%d\t%s=%d\t%s%s",
		s.Number,
		colorAddr("%#x", s.Call),
		s.Name,
		colorField("munge"), s.Munge,
		colorField("ret"), s.ReturnType,
		colorField("narg"), s.NArg,
		colorField("bytes"), s.ArgBytes,
		funcStr,
		isNew)
}

func getSyscallData() (*SyscallData, error) {
	var sdata SyscallData
	gzr, err := gzip.NewReader(bytes.NewReader(syscallData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()
	// Decoding the serialized data
	if err = gob.NewDecoder(gzr).Decode(&sdata); err != nil {
		return nil, fmt.Errorf("failed to decode syscall data; %v", err)
	}
	return &sdata, nil
}

// GetSyscallTable returns a map of system call table as array of sysent structs
func GetSyscallTable(m *macho.File) ([]Sysent, error) {
	var syscalls []Sysent
	var sysnoAddr uint64
	var maxSyscall int

	srcdata, err := getSyscallData()
	if err != nil {
		return nil, fmt.Errorf("failed to get embedded syscall data: %v", err)
	}

	sdata, err := getSyscallsData()
	if err != nil {
		return nil, fmt.Errorf("failed to get embedded syscall JSON data: %v", err)
	}

	maxSyscall = len(sdata.BsdSyscalls)

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		var err error
		m, err = m.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return nil, fmt.Errorf("failed to parse fileset entry com.apple.kernel; %v", err)
		}
	}

	if sec := m.Section("__DATA_CONST", "__const"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, err
		}

		sysents := make([]sysent, maxSyscall+20)

		pattern, err := hex.DecodeString(syscall2Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to decode pattern: %v", err)
		}

		if found := bytes.Index(dat, pattern); found > 0 {
			found -= (binary.Size(uint64(0)) * 5) // rewind to beginning of syscall table
			log.WithField("bsd_syscall_table", fmt.Sprintf("%#x", sec.Addr+uint64(found))).Infof("Found")

			if err := binary.Read(bytes.NewReader(dat[found:]), binary.LittleEndian, &sysents); err != nil {
				return nil, fmt.Errorf("failed to read syscalls sysent data: %v", err)
			}

			// fixup syscall table call/munge addresses
			for idx, sc := range sysents {
				isNew := false
				if sc.ReturnType > RET_UINT64_T || sc.ReturnType < RET_NONE {
					break
				}
				sysents[idx].Call = m.SlidePointer(sc.Call)
				sysents[idx].Munge = m.SlidePointer(sc.Munge)

				var name string
				if idx == 0 {
					name = "syscall"
					sysnoAddr = sc.Call
				} else if sc.Call == sysnoAddr {
					name = "nosys"
				} else {
					if sysents[idx].Munge == 0 &&
						sysents[idx].ReturnType == RET_INT_T &&
						sysents[idx].NArg == 0 &&
						sysents[idx].ArgBytes == 0 {
						name = "enosys"
					} else {
						name = unknownTrap
					}
				}

				// check if we have a name for this syscall in JSON data
				sc, err := sdata.GetBsdSyscallByNumber(idx)
				if err != nil { // not found
					// check if we have a name for this syscall in xnu src
					if n, ok := srcdata.Names[idx]; ok {
						name = n
					} else {
						isNew = true
					}
				} else { // found
					if name == "<unknown>" {
						name = sc.Name
					}
				}

				syscalls = append(syscalls, Sysent{
					Number: idx,
					Name:   name,
					DBName: sc.Name,
					Args:   sc.Arguments,
					New:    isNew,
					Old:    sc.Old,
					sysent: sysents[idx],
				})
			}
		} else {
			return nil, fmt.Errorf("failed to find begining of syscalls sysent data")
		}
	} else {
		return nil, fmt.Errorf("failed to find __DATA_CONST __const section in kernel")
	}

	return syscalls, nil
}

func ParseSyscallFiles(output string) error {
	var err error
	var syscalls SyscallData

	syscalls.Names, err = ParseSyscallHeader()
	if err != nil {
		return err
	}
	syscalls.Table, err = ParseSyscallsMaster()
	if err != nil {
		return err
	}

	buff := new(bytes.Buffer)

	of, err := os.Create(output)
	if err != nil {
		return err
	}
	defer of.Close()

	e := gob.NewEncoder(buff)

	// Encoding the map
	if err := e.Encode(syscalls); err != nil {
		return fmt.Errorf("failed to encode syscalls map to binary: %v", err)
	}

	gzw := gzip.NewWriter(of)
	defer gzw.Close()

	if _, err = buff.WriteTo(gzw); err != nil {
		return fmt.Errorf("failed to write syscalls map to gzip file: %v", err)
	}

	return nil
}

func ParseSyscallHeader() (map[int]string, error) {
	f, err := os.Open(syscallBetaHeader)
	if err != nil {
		ff, err := os.Open(syscallHeader)
		if err != nil {
			return nil, fmt.Errorf("failed to open syscall header: %v", err)
		}
		defer ff.Close()
		f = ff
	} else {
		defer f.Close()
	}

	r := bufio.NewReader(f)

	syscalls := make(map[int]string)

	re := regexp.MustCompile(`^#define\s+(?P<name_args>\S+)\s+(?P<num>\d+)$`)

	for {
		line, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read line: %v", err)
		}
		for _, match := range re.FindAllStringSubmatch(string(line), -1) {
			num, err := strconv.Atoi(match[2])
			if err != nil {
				return nil, fmt.Errorf("failed to convert %s to int: %v", match[2], err)
			}
			syscalls[num] = strings.TrimPrefix(match[1], "SYS_")
		}
	}

	if len(syscalls) == 0 {
		return nil, fmt.Errorf("failed to parse any syscalls from syscalls.master")
	}

	return syscalls, nil
}

func ParseSyscallsMaster() (map[int]sysMaster, error) {
	xnuTag, err := download.GetLatestTag("xnu", "", false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to query xnu github repo: %v", err)
	}

	resp, err := http.Get(fmt.Sprintf("https://raw.githubusercontent.com/apple-oss-distributions/xnu/%s/bsd/kern/syscalls.master", xnuTag))
	if err != nil {
		return nil, fmt.Errorf("failed to get syscalls.master: %w", err)
	}
	defer resp.Body.Close()

	r := bufio.NewReader(resp.Body)

	re, err := regexp.Compile(`^(?P<num>\d+)\s+(?P<audit>[A-Z0-9_]+)\s+(?P<files>[A-Z]+)\s+(?P<name_args>.+)$`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %v", err)
	}

	syscalls := make(map[int]sysMaster)

	for {
		line, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read line: %v", err)
		}
		for _, match := range re.FindAllStringSubmatch(string(line), -1) {
			num, err := strconv.Atoi(match[1])
			if err != nil {
				return nil, fmt.Errorf("failed to convert %s to int: %v", match[1], err)
			}
			if _, ok := syscalls[num]; ok { // already have this syscall
				if match[2] != "AUE_NULL" {
					syscalls[num] = sysMaster{
						Audit:       match[2],
						Files:       match[3],
						NameAndArgs: strings.Replace(match[4], " NO_SYSCALL_STUB", "", -1),
					}
				}
			} else {
				syscalls[num] = sysMaster{
					Audit:       match[2],
					Files:       match[3],
					NameAndArgs: strings.Replace(match[4], " NO_SYSCALL_STUB", "", -1),
				}
			}
		}
	}

	if len(syscalls) == 0 {
		return nil, fmt.Errorf("failed to parse any syscalls from syscalls.master")
	}

	return syscalls, nil
}
