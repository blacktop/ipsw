package ota

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/xz"
	"github.com/pkg/errors"
	// "github.com/danielrh/go-xz"
)

const (
	pbzxMagic     = 0x70627a78
	hasMoreChunks = 0x800000
)

type pbzxHeader struct {
	Magic            uint32
	UncompressedSize uint64
}

// headerMagic stores the magic bytes for the header
var headerMagic = []byte{0xfd, '7', 'z', 'X', 'Z', 0x00}

// HeaderLen provides the length of the xz file header.
const HeaderLen = 12

type xzHeader struct {
	Flags uint64
	Size  uint64
}

type entry struct {
	Usually_0x210Or_0x110 uint32
	Usually_0x00_00       uint16 //_00_00;
	FileSize              uint32
	Whatever              uint16
	TimestampLikely       uint64
	Usually_0x20          uint16
	NameLen               uint16
	Uid                   uint16
	Gid                   uint16
	Perms                 uint16
	//  char name[0];
	// Followed by file contents
}

// Extract extracts and decompresses OTA payload files
func Extract(otaZIP string) error {

	zr, err := zip.OpenReader(otaZIP)
	if err != nil {
		return errors.Wrap(err, "failed to open ota zip")
	}
	defer zr.Close()

	var validPayload = regexp.MustCompile(`payload.0\d+$`)

	for _, f := range zr.File {
		if validPayload.MatchString(f.Name) {
			fmt.Println(f.Name)
			if strings.Contains(f.Name, "payload.004") {
				err = ParseOTA(f)
				if err != nil {
					log.Error(err.Error())
				}
			}
		}
	}

	return nil
}

// ParseOTA parses a ota payload file inside the zip
func ParseOTA(payload *zip.File) error {

	pData := make([]byte, payload.UncompressedSize64)

	rc, err := payload.Open()
	if err != nil {
		return errors.Wrapf(err, "failed to open file in zip: %s", payload.Name)
	}

	io.ReadFull(rc, pData)
	rc.Close()

	pr := bytes.NewReader(pData)

	var pbzx pbzxHeader
	if err := binary.Read(pr, binary.BigEndian, &pbzx); err != nil {
		return err
	}

	if pbzx.Magic != pbzxMagic {
		return errors.New("src not a pbzx stream")
	}

	f, err := os.Create(filepath.Base(payload.Name) + ".xz")
	if err != nil {
		return errors.Wrapf(err, "failed to create file: %s", filepath.Base(payload.Name)+".xz")
	}
	defer f.Close()

	for {
		var xzTag xzHeader
		if err := binary.Read(pr, binary.BigEndian, &xzTag); err != nil {
			return err
		}

		xzBuf := make([]byte, xzTag.Size)
		if err := binary.Read(pr, binary.BigEndian, &xzBuf); err != nil {
			return err
		}
		// xr := xz.NewDecompressionReader(bytes.NewReader(xzBuf))
		xr, err := xz.NewReader(bytes.NewReader(xzBuf))
		if err != nil {
			return err
		}
		dstBuf := make([]byte, pbzx.UncompressedSize)
		_, err = xr.Read(dstBuf)
		if err != nil {
			return err
		}
		// write chunk to file
		f.Write(dstBuf)

		rr := bytes.NewReader(dstBuf)
		var e entry
		if err := binary.Read(rr, binary.BigEndian, &e); err != nil {
			return err
		}
		fileName := make([]byte, e.NameLen)
		if err := binary.Read(rr, binary.BigEndian, &fileName); err != nil {
			return err
		}
		fmt.Println(string(fileName))

		if (xzTag.Flags & hasMoreChunks) != 0 {
			break
		}
	}

	f.Sync()

	return nil
}
