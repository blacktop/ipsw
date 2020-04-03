// +build linux,cgo darwin,cgo

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

	"github.com/blacktop/go-macho"

	"github.com/apex/log"
	lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/lzss"
	"github.com/pkg/errors"
)

const (
	lzfseEncodeLSymbols       = 20
	lzfseEncodeMSymbols       = 20
	lzfseEncodeDSymbols       = 64
	lzfseEncodeLiteralSymbols = 256
	lzssPadding               = 0x16c
)

// Img4 Kernelcache object
type Img4 struct {
	IM4P    string
	Name    string
	Version string
	Data    []byte
}

// A LzssHeader represents the LZSS header
type LzssHeader struct {
	CompressionType  uint32 // 0x636f6d70 "comp"
	Signature        uint32 // 0x6c7a7373 "lzss"
	CheckSum         uint32 // Likely CRC32
	UncompressedSize uint32
	CompressedSize   uint32
	Padding          [lzssPadding]byte
}

// LzfseCompressedBlockHeaderV2 represents the lzfse header
type LzfseCompressedBlockHeaderV2 struct {
	Magic        uint32 // "bvx2"
	NumRawBytes  uint32
	PackedFields [3]uint64
	Freq         [2 * (lzfseEncodeLSymbols + lzfseEncodeMSymbols + lzfseEncodeDSymbols + lzfseEncodeLiteralSymbols)]uint8
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
	utils.Indent(log.Info, 2)("Parsing Kernelcache IMG4")

	// NOTE: openssl asn1parse -i -inform DER -in kernelcache.iphone10 | less (to get offset)
	//       openssl asn1parse -i -inform DER -in kernelcache.iphone10 -strparse OFFSET -noout -out lzfse.bin
	var i Img4
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Kernelcache")
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

// Extract extracts and decompresses a lernelcache from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting Kernelcache from IPSW")
	kcaches, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		if strings.Contains(f.Name, "kernelcache") {
			return true
		}
		return false
	})
	if err != nil {
		return errors.Wrap(err, "failed extract kernelcache from ipsw")
	}
	i, err := info.Parse(ipsw)
	if err != nil {
		return errors.Wrap(err, "failed to parse ipsw info")
	}
	for _, kcache := range kcaches {
		content, err := ioutil.ReadFile(kcache)
		if err != nil {
			return errors.Wrap(err, "failed to read Kernelcache")
		}

		kc, err := ParseImg4Data(content)
		if err != nil {
			return errors.Wrap(err, "failed parse compressed kernelcache")
		}

		dec, err := DecompressData(kc)
		if err != nil {
			return errors.Wrap(err, "failed to decompress kernelcache")
		}
		for _, folder := range i.GetKernelCacheFolders(kcache) {
			os.Mkdir(folder, os.ModePerm)
			fname := filepath.Join(folder, "kernelcache."+strings.ToLower(i.Plists.GetOSType()))
			err = ioutil.WriteFile(fname, dec, 0644)
			if err != nil {
				return errors.Wrap(err, "failed to decompress kernelcache")
			}
			utils.Indent(log.Info, 2)("Created " + fname)
			os.Remove(kcache)
		}
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
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}
	// defer os.Remove(kcache)

	utils.Indent(log.Info, 2)("Decompressing Kernelcache")
	dec, err := DecompressData(kc)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}

	err = ioutil.WriteFile(kcache+".decompressed", dec, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	utils.Indent(log.Info, 2)("Created " + kcache + ".decompressed")
	return nil
}

// DecompressData decompresses compressed kernelcache []byte data
func DecompressData(cc *CompressedCache) ([]byte, error) {
	utils.Indent(log.Info, 2)("Decompressing Kernelcache")

	if bytes.Contains(cc.Magic, []byte("bvx2")) { // LZFSE
		utils.Indent(log.Info, 2)("Kernelcache is LZFSE compressed")
		lzfseHeader := LzfseCompressedBlockHeaderV2{}
		// Read entire file header.
		if err := binary.Read(bytes.NewBuffer(cc.Data[:1000]), binary.BigEndian, &lzfseHeader); err != nil {
			return nil, err
		}
		cc.Header = lzfseHeader

		decData := lzfse.DecodeBuffer(cc.Data)

		fat, err := macho.NewFatFile(bytes.NewReader(decData))
		if errors.Is(err, macho.ErrNotFat) {
			return decData, nil
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
		return decData[fat.Arches[0].Offset:], nil

	} else if bytes.Contains(cc.Magic, []byte("comp")) { // LZSS
		utils.Indent(log.Debug, 1)("kernelcache is LZSS compressed")
		buffer := bytes.NewBuffer(cc.Data)
		lzssHeader := LzssHeader{}
		// Read entire file header.
		if err := binary.Read(buffer, binary.BigEndian, &lzssHeader); err != nil {
			return nil, err
		}

		msg := fmt.Sprintf("compressed size: %d, uncompressed: %d. checkSum: 0x%x",
			lzssHeader.CompressedSize,
			lzssHeader.UncompressedSize,
			lzssHeader.CheckSum,
		)
		utils.Indent(log.Debug, 1)(msg)

		cc.Header = lzssHeader

		if int(lzssHeader.CompressedSize) > cc.Size {
			return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, lzssHeader.CompressedSize)
		}

		// Read compressed file data.
		cc.Data = buffer.Next(int(lzssHeader.CompressedSize))
		dec := lzss.Decompress(cc.Data)
		return dec[:lzssHeader.UncompressedSize], nil
	}

	return []byte{}, errors.New("unsupported compression")
}

// RemoteParse parses plist files in a remote ipsw file
func RemoteParse(zr *zip.Reader) error {

	ipsw, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		if strings.Contains(f.Name, "kernelcache.") {
			for _, folder := range ipsw.GetKernelCacheFolders(f.Name) {
				fname := filepath.Join(folder, "kernelcache."+strings.ToLower(ipsw.Plists.GetOSType()))
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
						return errors.Wrap(err, "failed parse compressed kernelcache")
					}

					dec, err := DecompressData(kcomp)
					if err != nil {
						return errors.Wrap(err, "failed to decompress kernelcache")
					}

					os.Mkdir(folder, os.ModePerm)
					err = ioutil.WriteFile(fname, dec, 0644)
					if err != nil {
						return errors.Wrap(err, "failed to decompress kernelcache")
					}
				} else {
					log.Warnf("kernelcache already exists: %s", fname)
				}
			}
		}
	}

	return nil
}
