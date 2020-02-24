// +build !windows,cgo

package ota

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/dustin/go-humanize"

	// "github.com/blacktop/xz"
	"github.com/danielrh/go-xz"
	"github.com/pkg/errors"
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

func sortFileBySize(files []*zip.File) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].UncompressedSize64 > files[j].UncompressedSize64
	})
}

// Extract extracts and decompresses OTA payload files
func Extract(otaZIP, extractPattern string, listFiles bool) error {

	zr, err := zip.OpenReader(otaZIP)
	if err != nil {
		return errors.Wrap(err, "failed to open ota zip")
	}
	defer zr.Close()

	var validPayload = regexp.MustCompile(`payload.0\d+$`)

	sortFileBySize(zr.File)

	for _, f := range zr.File {
		if validPayload.MatchString(f.Name) {
			log.WithFields(log.Fields{"filename": f.Name, "size": humanize.Bytes(f.UncompressedSize64)}).Debug("Processing OTA file")
			err = ParseOTA(f, listFiles, extractPattern)
			if err != nil {
				log.Error(err.Error())
			}
		}
	}

	return nil
}

func RemoteParseOTA(zr *zip.Reader) error {

	var validPayload = regexp.MustCompile(`payload.0\d+$`)

	sortFileBySize(zr.File)

	for _, f := range zr.File {
		if validPayload.MatchString(f.Name) {
			log.WithFields(log.Fields{"filename": f.Name, "size": humanize.Bytes(f.UncompressedSize64)}).Debug("Processing OTA file")
			err := ParseOTA(f, false, "dyld_shared_cache_")
			if err != nil {
				log.Error(err.Error())
			}
			return nil
		}
	}

	return fmt.Errorf("dyld_shared_cache not found")
}

// ParseOTA parses a ota payload file inside the zip
func ParseOTA(payload *zip.File, listFiles bool, extractPattern string) error {
	var w *tabwriter.Writer

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

	// f, err := os.Create(filepath.Base(payload.Name) + ".xz")
	// if err != nil {
	// 	return errors.Wrapf(err, "failed to create file: %s", filepath.Base(payload.Name)+".xz")
	// }
	// defer f.Close()

	xzBuf := new(bytes.Buffer)

	for {
		var xzTag xzHeader
		if err := binary.Read(pr, binary.BigEndian, &xzTag); err != nil {
			return err
		}

		xzChunkBuf := make([]byte, xzTag.Size)
		if err := binary.Read(pr, binary.BigEndian, &xzChunkBuf); err != nil {
			return err
		}
		xr := xz.NewDecompressionReader(bytes.NewReader(xzChunkBuf))
		// xr, err := xz.NewReader(bytes.NewReader(xzBuf))
		// if err != nil {
		// 	return err
		// }
		dstBuf := make([]byte, pbzx.UncompressedSize)
		xzBuf.Grow(int(pbzx.UncompressedSize))

		_, err = xr.Read(dstBuf)
		if err != nil {
			return err
		}

		// xzBuf.ReadFrom(xr)
		xzBuf.Write(dstBuf)

		if (xzTag.Flags & hasMoreChunks) == 0 {
			// fmt.Printf("0x%x\n", xzTag.Flags)
			xr.Close()
			break
		}
	}

	rr := bytes.NewReader(xzBuf.Bytes())

	if listFiles {
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
	}

	for {
		var e entry
		if err := binary.Read(rr, binary.BigEndian, &e); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		if e.Usually_0x210Or_0x110 != 0x10010000 && e.Usually_0x210Or_0x110 != 0x10020000 && e.Usually_0x210Or_0x110 != 0x10030000 {
			// 0x10030000 seem to be framworks and other important platform binaries
			// if e.Usually_0x210Or_0x110 != 0 {
			// 	log.Warnf("found unknown entry flag: 0x%x", e.Usually_0x210Or_0x110)
			// }
			break
		}

		fileName := make([]byte, e.NameLen)
		if err := binary.Read(rr, binary.BigEndian, &fileName); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		// if e.Usually_0x20 != 0x20 {
		// 	fmt.Printf("%s: %#v\n", fileName, e)
		// }

		// if e.Usually_0x00_00 != 0 {
		// 	fmt.Printf("%s: %#v\n", fileName, e)
		// }

		if e.Usually_0x210Or_0x110 == 0x10030000 {
			fmt.Printf("%s (%s): %#v\n", fileName, os.FileMode(e.Perms), e)
		}

		if listFiles {
			fmt.Fprintf(w, "%s\tuid=%d\tgid=%d\t%s\t%s\n", os.FileMode(e.Perms), e.Uid, e.Gid, humanize.Bytes(uint64(e.FileSize)), fileName)
		}

		if len(extractPattern) > 0 {
			if strings.Contains(strings.ToLower(string(fileName)), strings.ToLower(extractPattern)) {
				fileBytes := make([]byte, e.FileSize)
				if err := binary.Read(rr, binary.BigEndian, &fileBytes); err != nil {
					if err == io.EOF {
						break
					}
					return err
				}
				log.Infof("Extracting %s uid=%d, gid=%d, %s, %s\n", os.FileMode(e.Perms), e.Uid, e.Gid, humanize.Bytes(uint64(e.FileSize)), fileName)
				err = ioutil.WriteFile(filepath.Base(string(fileName)), fileBytes, 0644)
				if err != nil {
					return err
				}
			}
		} else {
			rr.Seek(int64(e.FileSize), io.SeekCurrent)
		}
	}

	if listFiles {
		w.Flush()
	}

	return nil
}
