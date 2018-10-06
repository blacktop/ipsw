package kernelcache

import (
	"archive/zip"
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/get-ipsws/lzss"
	"github.com/blacktop/get-ipsws/utils"
	"github.com/pkg/errors"
)

// A LzssHeader represents the LZSS header
type LzssHeader struct {
	Signature        [8]byte // "complzss"
	Unknown          uint32  // Likely CRC32. But who cares, anyway?
	UncompressedSize uint32
	CompressedSize   uint32
	Unknown1         uint32 // 1
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Header LzssHeader
	Size   int64
	Data   []byte
}

// Open opens the named file using os.Open and prepares it for use as a compressed kernelcache.
func Open(name string) (*CompressedCache, error) {
	log.Info("Parsing Compressed Kernelcache")
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	cc := new(CompressedCache)
	cc.Size = fi.Size()

	dat := make([]byte, 1000)
	_, err = f.Read(dat)
	if err != nil {
		return nil, err
	}

	// find lzss magic
	hStart := bytes.Index(dat, []byte("complzss"))

	// Read entire file header.
	f.Seek(int64(hStart), 0)
	if err := binary.Read(f, binary.BigEndian, &cc.Header); err != nil {
		return nil, err
	}

	// Compressed Size: 17842843, Uncompressed: 35727352. Unknown (CRC?): 0x3f9543fd, Unknown 1: 0x1
	msg := fmt.Sprintf("compressed size: %d, uncompressed: %d. unknown: 0x%x, unknown 1: 0x%x",
		cc.Header.CompressedSize,
		cc.Header.UncompressedSize,
		cc.Header.Unknown,
		cc.Header.Unknown1,
	)
	utils.Indent(log.Info)(msg)

	// find compressed kernel 0xfeedfa.. start address
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, 0xfeedfacf)
	dStart := bytes.Index(dat, buf)
	msg = fmt.Sprintf("found compressed kernel at: %d", dStart)
	utils.Indent(log.Debug)(msg)

	if int64(cc.Header.CompressedSize) > cc.Size {
		return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, cc.Header.CompressedSize)
	}

	// Read entire file data.
	cc.Data = make([]byte, cc.Size-int64(dStart), int64(cc.Header.CompressedSize))
	n, err := f.ReadAt(cc.Data, int64(dStart-1))
	if err != nil {
		return nil, err
	}
	msg = fmt.Sprintf("read %d bytes of data from file", n)
	utils.Indent(log.Debug)(msg)

	return cc, nil
}

// Extract extracts and decompresses a lernelcache from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting Kernelcache from IPSW")
	kcache, err := Unzip(ipsw, "")
	if err != nil {
		return errors.Wrap(err, "failed extract kernelcache from ipsw")
	}
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

// Unzip - https://stackoverflow.com/a/24792688
func Unzip(src, dest string) (string, error) {
	var kcacheName string
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		if strings.Contains(f.Name, "kernelcache") {
			kcacheName = path.Base(f.Name)
			err := extractAndWriteFile(f)
			if err != nil {
				return "", err
			}
		}
	}

	return kcacheName, nil
}

// ParseMachO parses the kernelcache as a mach-o
func ParseMachO(name string) error {
	f, err := macho.Open(name)
	if err != nil {
		return err
	}

	fmt.Println(f.FileHeader)

	return nil
}
