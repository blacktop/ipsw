package kernelcache

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
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

// A LzssHeader represents the LZSS header
type LzssHeader struct {
	CompressionType  uint32 // 0x636f6d70 "comp"
	Signature        uint32 // 0x6c7a7373 "lzss"
	CheckSum         uint32 // Likely CRC32
	UncompressedSize uint32
	CompressedSize   uint32
	Padding          [0x16c]byte
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Header LzssHeader
	Size   int
	Data   []byte
}

// ParseImg4Data parses a img4 data containing a compressed kernelcache.
func ParseImg4Data(data []byte) (*CompressedCache, error) {
	utils.Indent(log.Info)("Parsing Compressed Kernelcache")

	var i Img4
	// NOTE: openssl asn1parse -i -inform DER -in kernelcache.iphone10
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Kernelcache")
	}

	buffer := bytes.NewBuffer(i.Data)

	cc := CompressedCache{Size: buffer.Len()}

	// Read entire file header.
	if err := binary.Read(buffer, binary.BigEndian, &cc.Header); err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("compressed size: %d, uncompressed: %d. checkSum: 0x%x",
		cc.Header.CompressedSize,
		cc.Header.UncompressedSize,
		cc.Header.CheckSum,
	)
	utils.Indent(log.Debug)(msg)

	if int(cc.Header.CompressedSize) > cc.Size {
		return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, cc.Header.CompressedSize)
	}

	// Read compressed file data.
	cc.Data = buffer.Next(int(cc.Header.CompressedSize))

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

	for _, kcache := range kcaches {
		content, err := ioutil.ReadFile(kcache)
		if err != nil {
			return errors.Wrap(err, "failed to read Kernelcache")
		}

		kc, err := ParseImg4Data(content)
		if err != nil {
			return errors.Wrap(err, "failed parse compressed kernelcache")
		}

		utils.Indent(log.Info)("Decompressing Kernelcache")
		dec := lzss.Decompress(kc.Data)
		err = ioutil.WriteFile(kcache+".decompressed", dec[:kc.Header.UncompressedSize], 0644)
		if err != nil {
			return errors.Wrap(err, "failed to decompress kernelcache")
		}
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
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}
	// defer os.Remove(kcache)

	utils.Indent(log.Info)("Decompressing Kernelcache")
	dec := lzss.Decompress(kc.Data)
	err = ioutil.WriteFile(kcache+".decompressed", dec[:kc.Header.UncompressedSize], 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	return nil
}

// DecompressData decompresses compressed kernelcache []byte data
func DecompressData(cc *CompressedCache) []byte {
	utils.Indent(log.Info)("Decompressing Kernelcache")
	dec := lzss.Decompress(cc.Data)
	return dec[:cc.Header.UncompressedSize]
}