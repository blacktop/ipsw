package kernelcache

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io/ioutil"

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

// Open opens the named file using os.Open and prepares it for use as a compressed kernelcache.
func Open(name string) (*CompressedCache, error) {
	log.Info("Parsing Compressed Kernelcache")

	content, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read Kernelcache")
	}

	var i Img4
	// NOTE: openssl asn1parse -i -inform DER -in kernelcache.iphone10
	if _, err := asn1.Unmarshal(content, &i); err != nil {
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
	utils.Indent(log.Info)(msg)

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
	kcache, err := utils.Unzip(ipsw, "", "kernelcache", 20*1024*1024)
	if err != nil {
		return errors.Wrap(err, "failed extract kernelcache from ipsw")
	}
	// defer os.Remove(kcache)

	kc, err := Open(kcache)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}

	log.Info("Decompressing Kernelcache")
	dec := lzss.Decompress(kc.Data)
	err = ioutil.WriteFile(kcache+".decompressed", dec[:kc.Header.UncompressedSize], 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	return nil
}

// Decompress decompresses a lernelcache
func Decompress(kcache string) error {
	kc, err := Open(kcache)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}
	// defer os.Remove(kcache)

	log.Info("Decompressing Kernelcache")
	dec := lzss.Decompress(kc.Data)
	err = ioutil.WriteFile(kcache+".decompressed", dec[:kc.Header.UncompressedSize], 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	return nil
}
