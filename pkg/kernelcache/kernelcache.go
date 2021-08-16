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
	"strings"

	"github.com/apex/log"
	// lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/blacktop/lzss"
	"github.com/pkg/errors"
)

// Img4 Kernelcache object
type Img4 struct {
	IM4P    string
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
		return errors.Wrap(err, "failed to parse ipsw info")
	}

	folder := filepath.Join(destPath, i.GetFolder())

	for _, kcache := range kcaches {
		fname := i.GetKernelCacheFileName(kcache)
		// fname := fmt.Sprintf("%s.%s", strings.TrimSuffix(kcache, filepath.Ext(kcache)), strings.Join(i.GetDevicesForKernelCache(kcache), "_"))
		fname = filepath.Join(folder, fname)

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

		os.Mkdir(folder, os.ModePerm)

		err = ioutil.WriteFile(fname, dec, 0644)
		if err != nil {
			return errors.Wrap(err, "failed to write kernelcache")
		}
		utils.Indent(log.Info, 2)("Created " + fname)
		os.Remove(kcache)
	}

	return nil
}

// Decompress decompresses a compressed kernelcache
func Decompress(kcache string) error {
	content, err := ioutil.ReadFile(kcache)
	if err != nil {
		return errors.Wrap(err, "failed to read Kernelcache")
	}

	kc, err := ParseImg4Data(content)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache Img4")
	}
	// defer os.Remove(kcache)

	utils.Indent(log.Debug, 2)("Decompressing Kernelcache")
	dec, err := DecompressData(kc)
	if err != nil {
		return fmt.Errorf("failed to decompress kernelcache %s: %v", kcache, err)
	}

	err = ioutil.WriteFile(kcache+".decompressed", dec, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to write kernelcache")
	}
	utils.Indent(log.Info, 2)("Created " + kcache + ".decompressed")
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

	folder := filepath.Join(destPath, i.GetFolder())

	for _, f := range zr.File {
		if strings.Contains(f.Name, "kernelcache.") {
			fname := i.GetKernelCacheFileName(f.Name)
			// fname := fmt.Sprintf("%s.%s", strings.TrimSuffix(f.Name, filepath.Ext(f.Name)), strings.Join(i.GetDevicesForKernelCache(f.Name), "_"))
			fname = filepath.Join(folder, fname)
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

				os.Mkdir(folder, os.ModePerm)
				err = ioutil.WriteFile(fname, dec, 0644)
				if err != nil {
					return errors.Wrap(err, "failed to write kernelcache")
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Writing %s", fname))
			} else {
				log.Warnf("kernelcache already exists: %s", fname)
			}
			// }
		}
	}

	return nil
}

// RemoteParseV2 parses the kernelcache in a remote IPSW file
func RemoteParseV2(zr *zip.Reader, destFolder string) error {

	for _, f := range zr.File {
		if strings.Contains(f.Name, "kernelcache.") {
			fname := filepath.Join(destFolder, f.Name)
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
					return errors.Wrapf(err, "failed to decompress kernelcache %s", f.Name)
				}

				os.Mkdir(destFolder, os.ModePerm)
				err = ioutil.WriteFile(fname, dec, 0644)
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

	_, err := r.Read(buf.Bytes())
	if err != nil {
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
