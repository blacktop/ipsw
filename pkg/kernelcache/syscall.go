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
		return "none"
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
	Call       uint64     // implementing function
	Munge      uint64     // system call arguments munger for 32-bit process
	ReturnType returnType // system call return types
	NArg       int16      // number of args
	ArgBytes   uint16     // Total size of arguments in bytes for 32-bit system calls
}

type Sysent struct {
	Name   string
	Number int
	Proto  string
	New    bool
	sysent
}

func (s Sysent) String() string {
	var isNew string
	if s.New {
		isNew = "(found 🆕 syscall)"
	}
	return fmt.Sprintf("%d:\t%s\tcall=%#x\tmunge=%#x\tret=%s\tnarg=%d (bytes=%d)\t%s%s", s.Number, s.Name, s.Call, s.Munge, s.ReturnType, s.NArg, s.ArgBytes, s.Proto, isNew)
}

func getSyscallData() (*SyscallData, error) {
	var sdata SyscallData
	gzr, err := gzip.NewReader(bytes.NewReader(syscallData))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()
	// Decoding the serialized data
	err = gob.NewDecoder(gzr).Decode(&sdata)
	if err != nil {
		return nil, fmt.Errorf("failed to decode syscall data; %v", err)
	}
	return &sdata, nil
}

// GetSyscallTable returns a map of system call table as array of sysent structs
func GetSyscallTable(m *macho.File) ([]Sysent, error) {
	var syscalls []Sysent
	var SYS_MAXSYSCALL int

	sdata, err := getSyscallData()
	if err != nil {
		return nil, fmt.Errorf("failed to get embedded syscall data: %v", err)
	}
	for k, v := range sdata.Names {
		if v == "MAXSYSCALL" {
			SYS_MAXSYSCALL = k
		}
	}

	if m.FileTOC.FileHeader.Type == types.FileSet {
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

		sysents := make([]sysent, SYS_MAXSYSCALL+20)

		pattern, err := hex.DecodeString(syscall2Pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to decode pattern: %v", err)
		}

		if found := bytes.Index(dat, pattern); found > 0 {
			found -= (binary.Size(uint64(0)) * 5) // rewind to beginning of syscall table
			log.Debugf("found at addr: %#x\n", sec.Addr+uint64(found))
			if err := binary.Read(bytes.NewReader(dat[found:]), binary.LittleEndian, &sysents); err != nil {
				return nil, fmt.Errorf("failed to read syscalls sysent data: %v", err)
			}
			// fixup syscall table call/munge addresses
			for idx, sc := range sysents {
				isNew := false
				if sc.ReturnType > RET_UINT64_T || sc.ReturnType < RET_NONE {
					break
				}
				if idx > SYS_MAXSYSCALL {
					isNew = true
				}
				sysents[idx].Call = m.SlidePointer(sc.Call)
				sysents[idx].Munge = m.SlidePointer(sc.Munge)
				name := "enosys"
				if n, ok := sdata.Names[idx]; ok {
					name = n
				}
				var proto string
				if sm, ok := sdata.Table[idx]; ok {
					proto = sm.NameAndArgs
				}
				syscalls = append(syscalls, Sysent{
					Name:   name,
					Number: idx,
					Proto:  proto,
					New:    isNew,
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
		return nil, fmt.Errorf("failed to open syscall beta header: %v", err)
	}
	defer f.Close()

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
