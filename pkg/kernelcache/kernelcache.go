package kernelcache

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/apex/log"
	// lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/blacktop/lzss"
	"github.com/pkg/errors"
)

// Img4 Kernelcache object
type Img4 struct {
	IMG4    string
	IM4P    string `asn1:"optional"`
	Name    string
	Version string
	Data    []byte
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Magic  []byte
	Header interface{}
	Size   int
	Data   []byte
}

type Version struct {
	Kernel struct {
		Darwin string    `json:"darwin,omitempty"`
		Date   time.Time `json:"date,omitempty"`
		XNU    string    `json:"xnu,omitempty"`
		Type   string    `json:"type,omitempty"`
		Arch   string    `json:"arch,omitempty"`
		CPU    string    `json:"cpu,omitempty"`
	} `json:"kernel,omitempty"`
	LLVM struct {
		Version string   `json:"version,omitempty"`
		Clang   string   `json:"clang,omitempty"`
		Flags   []string `json:"flags,omitempty"`
	} `json:"llvm,omitempty"`
	rawKernel string
	rawLLVM   string
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

	var i Img4
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

// Extract extracts and decompresses a kernelcache from ipsw
func Extract(ipsw, destPath string) error {
	log.Debug("Extracting Kernelcache from IPSW")
	kcaches, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		return strings.Contains(f.Name, "kernelcache")
	})
	if err != nil {
		return errors.Wrap(err, "failed extract kernelcache from ipsw")
	}

	i, err := info.Parse(ipsw)
	if err != nil {
		return fmt.Errorf("failed to parse ipsw info: %v", err)
	}

	for _, kcache := range kcaches {
		fname := i.GetKernelCacheFileName(kcache)
		// fname := fmt.Sprintf("%s.%s", strings.TrimSuffix(kcache, filepath.Ext(kcache)), strings.Join(i.GetDevicesForKernelCache(kcache), "_"))
		fname = filepath.Join(destPath, fname)

		content, err := ioutil.ReadFile(kcache)
		if err != nil {
			return errors.Wrap(err, "failed to read Kernelcache")
		}

		kc, err := ParseImg4Data(content)
		if err != nil {
			return errors.Wrap(err, "failed parse compressed kernelcache Img4")
		}

		dec, err := DecompressData(kc)
		if err != nil {
			return errors.Wrap(err, "failed to decompress kernelcache")
		}

		os.Mkdir(destPath, 0750)

		err = ioutil.WriteFile(fname, dec, 0660)
		if err != nil {
			return errors.Wrap(err, "failed to write kernelcache")
		}
		utils.Indent(log.Info, 2)("Created " + fname)
		os.Remove(kcache)
	}

	return nil
}

// Decompress decompresses a compressed kernelcache
func Decompress(kcache, outputDir string) error {
	content, err := ioutil.ReadFile(kcache)
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

	err = ioutil.WriteFile(kcache, dec, 0660)
	if err != nil {
		return errors.Wrap(err, "failed to write kernelcache")
	}
	utils.Indent(log.Info, 2)("Created " + kcache)
	return nil
}

// DecompressKernelManagement decompresses a compressed KernelManagement_host kernelcache
func DecompressKernelManagement(kcache, outputDir string) error {
	content, err := ioutil.ReadFile(kcache)
	if err != nil {
		return errors.Wrap(err, "failed to read Kernelcache")
	}

	km, err := img4.ParseImg4(bytes.NewReader(content))
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache Img4")
	}

	kcache = filepath.Join(outputDir, kcache+".decompressed")
	os.MkdirAll(filepath.Dir(kcache), 0755)

	if bytes.Contains(km.IM4P.Data[:4], []byte("bvx2")) {
		utils.Indent(log.Debug, 2)("Detected LZFSE compression")
		dat, err := lzfse.NewDecoder(km.IM4P.Data).DecodeBuffer()
		if err != nil {
			return fmt.Errorf("failed to decompress kernelcache %s: %v", kcache, err)
		}

		if err = os.WriteFile(kcache, dat, 0660); err != nil {
			return fmt.Errorf("failed to write kernelcache %s: %v", kcache, err)
		}
	} else {
		if err = os.WriteFile(kcache, km.IM4P.Data, 0660); err != nil {
			return fmt.Errorf("failed to write kernelcache %s: %v", kcache, err)
		}
	}

	return nil
}

// DecompressData decompresses compressed kernelcache []byte data
func DecompressData(cc *CompressedCache) ([]byte, error) {
	utils.Indent(log.Debug, 2)("Decompressing Kernelcache")

	if bytes.Contains(cc.Magic, []byte("bvx2")) { // LZFSE
		utils.Indent(log.Debug, 3)("Kernelcache is LZFSE compressed")

		// dat := lzfse.DecodeBuffer(cc.Data)
		// buf := new(bytes.Buffer)

		// _, err := buf.ReadFrom(lr)
		// if err != nil {
		// 	return nil, errors.Wrap(err, "failed to lzfse decompress kernelcache")
		// }

		dat, err := lzfse.NewDecoder(cc.Data).DecodeBuffer()
		if err != nil {
			return nil, errors.Wrap(err, "failed to lzfse decompress kernelcache")
		}

		fat, err := macho.NewFatFile(bytes.NewReader(dat))
		if errors.Is(err, macho.ErrNotFat) {
			return dat, nil
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
		return dat[fat.Arches[0].Offset:], nil

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

	return []byte{}, errors.New("unsupported compression")
}

// RemoteParse parses plist files in a remote ipsw file
func RemoteParse(zr *zip.Reader, destPath string) error {

	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return err
	}
	folder, err := i.GetFolder()
	if err != nil {
		log.Errorf("failed to get folder from remote zip metadata: %v", err)
	}
	destPath = filepath.Join(destPath, folder)

	for _, f := range zr.File {
		if strings.Contains(f.Name, "kernelcache.") {
			fname := i.GetKernelCacheFileName(f.Name)
			// fname := fmt.Sprintf("%s.%s", strings.TrimSuffix(f.Name, filepath.Ext(f.Name)), strings.Join(i.GetDevicesForKernelCache(f.Name), "_"))
			fname = filepath.Join(destPath, filepath.Clean(fname))
			if _, err := os.Stat(fname); os.IsNotExist(err) {
				kdata := make([]byte, f.UncompressedSize64)
				rc, err := f.Open()
				if err != nil {
					return errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
				}
				io.ReadFull(rc, kdata)
				rc.Close()

				kcomp, err := ParseImg4Data(kdata)
				if err != nil {
					return errors.Wrap(err, "failed parse kernelcache img4")
				}

				dec, err := DecompressData(kcomp)
				if err != nil {
					return errors.Wrapf(err, "failed to decompress kernelcache %s", fname)
				}

				os.Mkdir(destPath, 0750)
				err = ioutil.WriteFile(fname, dec, 0660)
				if err != nil {
					return errors.Wrap(err, "failed to write kernelcache")
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Writing %s", fname))
			} else {
				log.Warnf("kernelcache already exists: %s", fname)
			}
		}
	}

	return nil
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
					reKV := regexp.MustCompile(`^Darwin Kernel Version (?P<darwin>.+): (?P<date>.+); root:xnu-(?P<xnu>.+)/(?P<type>.+)_(?P<arch>.+)_(?P<cpu>.+)$`)
					if reKV.MatchString(s) {
						foundKV = true
						kv.rawKernel = s
						matches := reKV.FindStringSubmatch(s)
						kv.Kernel.Darwin = matches[reKV.SubexpIndex("darwin")]
						// TODO: confirm that day is not in form 02 for day
						kv.Kernel.Date, err = time.Parse("Mon Jan 2 15:04:05 MST 2006", matches[reKV.SubexpIndex("date")])
						if err != nil {
							return nil, fmt.Errorf("failed to parse date %s: %v", matches[reKV.SubexpIndex("date")], err)
						}
						kv.Kernel.XNU = matches[reKV.SubexpIndex("xnu")]
						kv.Kernel.Type = matches[reKV.SubexpIndex("type")]
						kv.Kernel.Arch = matches[reKV.SubexpIndex("arch")]
						kv.Kernel.CPU = matches[reKV.SubexpIndex("cpu")]
					}

					reLLVM := regexp.MustCompile(`^Apple LLVM (?P<version>.+) \(clang-(?P<clang>.+)\) \[(?P<flags>.+)\]$`)
					if reLLVM.MatchString(s) {
						foundLLVM = true
						kv.rawLLVM = s
						matches := reLLVM.FindStringSubmatch(s)
						kv.LLVM.Version = matches[reLLVM.SubexpIndex("version")]
						kv.LLVM.Clang = matches[reLLVM.SubexpIndex("clang")]
						kv.LLVM.Flags = strings.Split(matches[reLLVM.SubexpIndex("flags")], ", ")
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
