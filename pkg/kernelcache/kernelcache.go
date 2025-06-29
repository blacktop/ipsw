package kernelcache

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/comp"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/lzss"
	"github.com/pkg/errors"
)

// Im4p Kernelcache object
type Im4p struct {
	IM4P    string
	Name    string
	Version string
	Data    []byte
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Magic  []byte
	Header any
	Size   int
	Data   []byte
}

// KernelVersion represents the kernel version.
// swagger:model
type KernelVersion struct {
	// The darwin version
	Darwin string `json:"darwin,omitempty"`
	// The build date
	Date time.Time `json:"date"`
	// The xnu version
	XNU string `json:"xnu,omitempty"`
	// The kernel type
	Type string `json:"type,omitempty"`
	// The kernel architecture
	Arch string `json:"arch,omitempty"`
	// The kernel CPU
	CPU string `json:"cpu,omitempty"`
}

// LLVMVersion represents the LLVM version used to compile the kernel.
// swagger:model
type LLVMVersion struct {
	// The LLVM version
	Version string `json:"version,omitempty"`
	// The LLVM compiler
	Clang string `json:"clang,omitempty"`
	// The LLVM compiler flags
	Flags []string `json:"flags,omitempty"`
}

// Version represents the kernel version and LLVM version.
// swagger:response kernelcacheVersion
type Version struct {
	// swagger:model
	KernelVersion `json:"kernel"`
	// swagger:allOf
	LLVMVersion `json:"llvm"`
	rawKernel   string
	rawLLVM     string
}

func (v *Version) String() string {
	var llvm string
	if len(v.rawLLVM) > 0 {
		llvm = fmt.Sprintf("\n%s", v.rawLLVM)
	}
	return fmt.Sprintf("%s%s", v.rawKernel, llvm)
}

// ParseImg4Data parses a img4 data containing a compressed kernelcache.
func ParseImg4Data(data []byte) (*CompressedCache, error) {
	utils.Indent(log.Debug, 2)("Parsing Kernelcache IMG4")

	// NOTE: openssl asn1parse -i -inform DER -in kernelcache.iphone10 | less (to get offset)
	//       openssl asn1parse -i -inform DER -in kernelcache.iphone10 -strparse OFFSET -noout -out lzfse.bin

	var i Im4p
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse kernelcache")
	}

	cc := CompressedCache{
		Magic: make([]byte, 4),
		Size:  len(i.Data),
		Data:  i.Data,
	}

	// Read file header magic.
	if err := binary.Read(bytes.NewBuffer(i.Data[:4]), binary.BigEndian, &cc.Magic); err != nil {
		return nil, err
	}

	return &cc, nil
}

// Parse parses the compressed kernelcache Img4 data
func Parse(r io.ReadCloser) ([]byte, error) {
	var buf bytes.Buffer

	if _, err := r.Read(buf.Bytes()); err != nil {
		return nil, errors.Wrap(err, "failed to read data")
	}

	kcomp, err := ParseImg4Data(buf.Bytes())
	if err != nil {
		return nil, errors.Wrap(err, "failed parse kernelcache img4")
	}

	dec, err := DecompressData(kcomp)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress kernelcache")
	}
	r.Close()

	return dec, nil
}

// Decompress decompresses a compressed kernelcache
func Decompress(kcache, outputDir string) error {
	content, err := os.ReadFile(kcache)
	if err != nil {
		return errors.Wrap(err, "failed to read Kernelcache")
	}

	kc, err := ParseImg4Data(content)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache Img4")
	}

	utils.Indent(log.Debug, 2)("Decompressing Kernelcache")
	dec, err := DecompressData(kc)
	if err != nil {
		return fmt.Errorf("failed to decompress kernelcache %s: %v", kcache, err)
	}

	kcache = filepath.Join(outputDir, kcache+".decompressed")
	os.MkdirAll(filepath.Dir(kcache), 0755)

	err = os.WriteFile(kcache, dec, 0660)
	if err != nil {
		return errors.Wrap(err, "failed to write kernelcache")
	}
	utils.Indent(log.Info, 2)("Created " + kcache)
	return nil
}

// DecompressKernelManagement decompresses a compressed KernelManagement_host kernelcache
func DecompressKernelManagement(kcache, outputDir string) error {
	km, err := img4.Open(kcache)
	if err != nil {
		return fmt.Errorf("failed to parse kernelmanagement img4: %v", err)
	}

	data, err := km.Payload.GetData()
	if err != nil {
		return fmt.Errorf("failed to get kernelmanagement data: %v", err)
	}

	kcache = filepath.Join(outputDir, kcache+".decompressed")
	if err := os.MkdirAll(filepath.Dir(kcache), 0755); err != nil {
		return fmt.Errorf("failed to create output directory for %s: %v", kcache, err)
	}

	if err = os.WriteFile(kcache, data, 0660); err != nil {
		return fmt.Errorf("failed to write kernelcache %s: %v", kcache, err)
	}

	utils.Indent(log.Info, 2)("Created " + kcache)
	return nil
}

// DecompressKernelManagementData decompresses a compressed KernelManagement_host kernelcache's data
func DecompressKernelManagementData(kcache string) ([]byte, error) {
	km, err := img4.Open(kcache)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kernelmanagement img4: %v", err)
	}

	if km.Payload == nil {
		return nil, fmt.Errorf("kernelmanagement img4 payload is nil")
	}

	data, err := km.Payload.GetData()
	if err != nil {
		return nil, fmt.Errorf("failed to get kernelmanagement data: %v", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("kernelmanagement img4 payload data is empty")
	}

	return data, nil
}

// DecompressData decompresses compressed kernelcache []byte data
func DecompressData(cc *CompressedCache) ([]byte, error) {
	utils.Indent(log.Debug, 2)("Decompressing Kernelcache")

	if isLZFSE, err := magic.IsLZFSE(cc.Data); err != nil {
		return nil, fmt.Errorf("failed to check if kernelcache is lzfse compressed: %v", err)
	} else if isLZFSE {
		utils.Indent(log.Debug, 2)("Detected LZFSE compression")
		decompressed, err := comp.Decompress(cc.Data, comp.LZFSE)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress kernelcache: %v", err)
		}
		if len(decompressed) == 0 {
			return nil, fmt.Errorf("failed to LZFSE decompress kernelcache")
		}
		// check if kernelcache is fat/universal
		fat, err := macho.NewFatFile(bytes.NewReader(decompressed))
		if errors.Is(err, macho.ErrNotFat) {
			return decompressed, nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse fat mach-o")
		}
		defer fat.Close()

		// Sanity check
		if len(fat.Arches) > 1 {
			return nil, errors.New("found more than 1 mach-o fat file")
		}

		// Essentially: lipo -thin arm64e
		utils.Indent(log.Debug, 3)(fmt.Sprintf("Extracting arch '%s, %s' from single slice fat MachO file", fat.Arches[0].CPU, fat.Arches[0].SubCPU.String(fat.Arches[0].CPU)))
		return decompressed[fat.Arches[0].Offset:], nil
	} else if bytes.Contains(cc.Magic, []byte("comp")) { // LZSS
		utils.Indent(log.Debug, 3)("kernelcache is LZSS compressed")
		buffer := bytes.NewBuffer(cc.Data)
		lzssHeader := lzss.Header{}
		// Read entire file header.
		if err := binary.Read(buffer, binary.BigEndian, &lzssHeader); err != nil {
			return nil, err
		}

		msg := fmt.Sprintf("compressed size: %d, uncompressed: %d, checkSum: 0x%x",
			lzssHeader.CompressedSize,
			lzssHeader.UncompressedSize,
			lzssHeader.CheckSum,
		)
		utils.Indent(log.Debug, 3)(msg)

		cc.Header = lzssHeader

		if int(lzssHeader.CompressedSize) > cc.Size {
			return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, lzssHeader.CompressedSize)
		}

		// Read compressed file data.
		cc.Data = buffer.Next(int(lzssHeader.CompressedSize))
		dec := lzss.Decompress(cc.Data)
		return dec[:], nil
	} else if types.Magic(binary.LittleEndian.Uint64(cc.Data[0:8])) == types.Magic64 { // uncompressed
		return cc.Data, nil
	}

	return []byte{}, errors.New("unsupported compression (possibly encrypted)")
}

// Extract extracts and decompresses a kernelcache from ipsw
func Extract(ipsw, destPath, device string) (map[string][]string, error) {
	tmpDIR, err := os.MkdirTemp("", "ipsw_extract_kcache")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory to store SPTM im4p: %v", err)
	}
	defer os.RemoveAll(tmpDIR)

	kcaches, err := utils.Unzip(ipsw, tmpDIR, func(f *zip.File) bool {
		return strings.Contains(f.Name, "kernelcache")
	})
	if err != nil {
		return nil, fmt.Errorf("failed to unzip kernelcache: %v", err)
	}

	i, err := info.Parse(ipsw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ipsw info: %v", err)
	}

	artifacts := make(map[string][]string)
	for _, kcache := range kcaches {
		if len(device) > 0 && !slices.Contains(i.GetDevicesForKernelCache(kcache), device) {
			os.Remove(kcache)
			continue // skip if kernel not for given device
		}
		fname := i.GetKernelCacheFileName(kcache)
		fname = filepath.Join(destPath, fname)
		fname = filepath.Clean(fname)

		content, err := os.ReadFile(kcache)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read Kernelcache")
		}

		kc, err := ParseImg4Data(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse im4p kernelcache data: %v", err)
		}

		dec, err := DecompressData(kc)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress kernelcache data: %v", err)
		}

		if err := os.MkdirAll(filepath.Dir(fname), 0750); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %v", err)
		}
		if err := os.WriteFile(fname, dec, 0660); err != nil {
			return nil, fmt.Errorf("failed to write decompressed kernelcache: %v", err)
		}
		os.Remove(kcache)

		artifacts[fname] = i.GetDevicesForKernelCache(kcache)
	}

	return artifacts, nil
}

// RemoteParse parses plist files in a remote ipsw file
func RemoteParse(zr *zip.Reader, destPath, device string) (map[string][]string, error) {
	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return nil, err
	}

	artifacts := make(map[string][]string)

	for _, f := range zr.File {
		if strings.Contains(f.Name, "kernelcache.") {
			fname := filepath.Join(destPath, filepath.Clean(i.GetKernelCacheFileName(f.Name)))
			if len(device) > 0 && !slices.Contains(i.GetDevicesForKernelCache(f.Name), device) {
				continue // skip if kernel not for given device
			}
			if _, err := os.Stat(fname); os.IsNotExist(err) {
				kdata := make([]byte, f.UncompressedSize64)
				rc, err := f.Open()
				if err != nil {
					return nil, fmt.Errorf("failed to open kernelcache %s in zip: %v", f.Name, err)
				}
				io.ReadFull(rc, kdata)
				rc.Close()

				kcomp, err := ParseImg4Data(kdata)
				if err != nil {
					return nil, fmt.Errorf("failed to parse kernelcache im4p %s: %v", f.Name, err)
				}

				dec, err := DecompressData(kcomp)
				if err != nil {
					return nil, fmt.Errorf("failed to decompress kernelcache %s: %v", f.Name, err)
				}

				if err := os.MkdirAll(filepath.Dir(fname), 0750); err != nil {
					return nil, fmt.Errorf("failed to create destination directory: %v", err)
				}
				if err := os.WriteFile(fname, dec, 0660); err != nil {
					return nil, fmt.Errorf("failed to write kernelcache %s: %v", fname, err)
				}
				artifacts[fname] = i.GetDevicesForKernelCache(f.Name)
			} else {
				log.Warnf("kernelcache already exists: %s", fname)
			}
		}
	}

	return artifacts, nil
}

func GetVersion(m *macho.File) (*Version, error) {
	var kv Version

	kc := m

	if kc.FileTOC.FileHeader.Type == types.MH_FILESET {
		var err error
		kc, err = m.GetFileSetFileByName("kernel")
		if err != nil {
			return nil, fmt.Errorf("failed to parse fileset entry 'kernel': %v", err)
		}
	}

	if sec := kc.Section("__TEXT", "__const"); sec != nil {
		dat, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to read cstrings in %s.%s: %v", sec.Seg, sec.Name, err)
		}

		csr := bytes.NewBuffer(dat[:])

		foundKV := false
		foundLLVM := false

		for {
			s, err := csr.ReadString('\x00')

			if err == io.EOF {
				break
			}

			if err != nil {
				return nil, fmt.Errorf("failed to read string: %v", err)
			}

			s = strings.Trim(s, "\x00")

			if len(s) > 0 {
				if utils.IsASCII(s) {
					reKV := regexp.MustCompile(`^Darwin Kernel Version (?P<darwin>.+): (?P<date>.+); root:xnu.*-(?P<xnu>.+)/(?P<type>.+)_(?P<arch>.+)_(?P<cpu>.+)$`)
					if reKV.MatchString(s) {
						foundKV = true
						kv.rawKernel = s
						matches := reKV.FindStringSubmatch(s)
						kv.KernelVersion.Darwin = matches[reKV.SubexpIndex("darwin")]
						// TODO: confirm that day is not in form 02 for day
						kv.KernelVersion.Date, err = time.Parse("Mon Jan 2 15:04:05 MST 2006", matches[reKV.SubexpIndex("date")])
						if err != nil {
							return nil, fmt.Errorf("failed to parse date %s: %v", matches[reKV.SubexpIndex("date")], err)
						}
						kv.KernelVersion.XNU = matches[reKV.SubexpIndex("xnu")]
						kv.KernelVersion.Type = matches[reKV.SubexpIndex("type")]
						kv.KernelVersion.Arch = matches[reKV.SubexpIndex("arch")]
						kv.KernelVersion.CPU = matches[reKV.SubexpIndex("cpu")]
					}

					reLLVM := regexp.MustCompile(`^Apple LLVM (?P<version>.+) \(clang-(?P<clang>.+)\) \[(?P<flags>.+)\]$`)
					if reLLVM.MatchString(s) {
						foundLLVM = true
						kv.rawLLVM = s
						matches := reLLVM.FindStringSubmatch(s)
						kv.LLVMVersion.Version = matches[reLLVM.SubexpIndex("version")]
						kv.LLVMVersion.Clang = matches[reLLVM.SubexpIndex("clang")]
						kv.LLVMVersion.Flags = strings.Split(matches[reLLVM.SubexpIndex("flags")], ", ")
					}

					if foundKV && foundLLVM {
						break
					}
				}
			}
		}
	} else {
		return nil, fmt.Errorf("section __TEXT.__const not found in kernelcache (if this is a macOS kernel you might need to first extract the fileset entry)")
	}

	return &kv, nil
}
