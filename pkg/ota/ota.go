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

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/bom"
	"github.com/dustin/go-humanize"

	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
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
	ModTime               uint64
	Whatever              uint16
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

// List lists the files in the ota payloads
func List(otaZIP string) ([]os.FileInfo, error) {

	zr, err := zip.OpenReader(otaZIP)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open ota zip")
	}
	defer zr.Close()

	return parseBOM(&zr.Reader)
}

// RemoteList lists the files in a remote ota payloads
func RemoteList(zr *zip.Reader) ([]os.FileInfo, error) {
	return parseBOM(zr)
}

func parseBOM(zr *zip.Reader) ([]os.FileInfo, error) {
	var validPostBOM = regexp.MustCompile(`post.bom$`)

	for _, f := range zr.File {
		if validPostBOM.MatchString(f.Name) {
			r, err := f.Open()
			if err != nil {
				return nil, errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
			}
			bomData := make([]byte, f.UncompressedSize64)
			io.ReadFull(r, bomData)
			r.Close()
			return bom.Read(bytes.NewReader(bomData))
		}
	}

	return nil, fmt.Errorf("post.bom not found in zip")
}

// Extract extracts and decompresses OTA payload files
func Extract(otaZIP, extractPattern string) error {

	zr, err := zip.OpenReader(otaZIP)
	if err != nil {
		return errors.Wrap(err, "failed to open ota zip")
	}
	defer zr.Close()

	return parsePayload(&zr.Reader, extractPattern)
}

func getFolder(zr *zip.Reader) (string, error) {
	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse plists in remote zip")
	}

	folders := i.GetFolders()
	if len(folders) == 0 {
		return "", fmt.Errorf("failed to get folder")
	}

	return folders[0], nil
}

// RemoteExtract extracts and decompresses remote OTA payload files
func RemoteExtract(zr *zip.Reader, extractPattern string) error {

	var validPayload = regexp.MustCompile(`payload.0\d+$`)

	folder, err := getFolder(zr)
	if err != nil {
		return err
	}

	sortFileBySize(zr.File)

	for _, f := range zr.File {
		if validPayload.MatchString(f.Name) {
			log.WithFields(log.Fields{"filename": f.Name, "size": humanize.Bytes(f.UncompressedSize64)}).Debug("Processing OTA file")
			found, err := Parse(f, folder, extractPattern)
			if err != nil {
				log.Error(err.Error())
			}
			if found {
				return nil
			}
		}
	}

	return fmt.Errorf("dyld_shared_cache not found")
}

func parsePayload(zr *zip.Reader, extractPattern string) error {
	var validPayload = regexp.MustCompile(`payload.0\d+$`)

	folder, err := getFolder(zr)
	if err != nil {
		return err
	}

	sortFileBySize(zr.File)

	for _, f := range zr.File {
		if validPayload.MatchString(f.Name) {
			log.WithFields(log.Fields{"filename": f.Name, "size": humanize.Bytes(f.UncompressedSize64)}).Debug("Processing OTA file")
			found, err := Parse(f, folder, extractPattern)
			if err != nil {
				log.Error(err.Error())
			}
			if found {
				return nil
			}
		}
	}

	return fmt.Errorf("no files matched: %s", extractPattern)
}

// Parse parses a ota payload file inside the zip
func Parse(payload *zip.File, folder, extractPattern string) (bool, error) {

	pData := make([]byte, payload.UncompressedSize64)

	rc, err := payload.Open()
	if err != nil {
		return false, errors.Wrapf(err, "failed to open file in zip: %s", payload.Name)
	}

	io.ReadFull(rc, pData)
	rc.Close()

	pr := bytes.NewReader(pData)

	var pbzx pbzxHeader
	if err := binary.Read(pr, binary.BigEndian, &pbzx); err != nil {
		return false, err
	}

	if pbzx.Magic != pbzxMagic {
		return false, errors.New("src not a pbzx stream")
	}

	xzBuf := new(bytes.Buffer)

	for {
		var xzTag xzHeader
		if err := binary.Read(pr, binary.BigEndian, &xzTag); err != nil {
			return false, err
		}

		xzChunkBuf := make([]byte, xzTag.Size)
		if err := binary.Read(pr, binary.BigEndian, &xzChunkBuf); err != nil {
			return false, err
		}

		xr, err := xz.NewReader(bytes.NewReader(xzChunkBuf))
		if err != nil {
			return false, err
		}

		io.Copy(xzBuf, xr)

		if (xzTag.Flags & hasMoreChunks) == 0 {
			break
		}
	}

	rr := bytes.NewReader(xzBuf.Bytes())

	for {
		var e entry
		if err := binary.Read(rr, binary.BigEndian, &e); err != nil {
			if err == io.EOF {
				break
			}
			return false, err
		}

		// 0x10030000 seem to be framworks and other important platform binaries (or symlinks?)
		if e.Usually_0x210Or_0x110 != 0x10010000 && e.Usually_0x210Or_0x110 != 0x10020000 && e.Usually_0x210Or_0x110 != 0x10030000 {
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
			return false, err
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

		if len(extractPattern) > 0 {
			if strings.Contains(strings.ToLower(string(fileName)), strings.ToLower(extractPattern)) {
				fileBytes := make([]byte, e.FileSize)
				if err := binary.Read(rr, binary.BigEndian, &fileBytes); err != nil {
					if err == io.EOF {
						break
					}
					return false, err
				}

				os.Mkdir(folder, os.ModePerm)
				fname := filepath.Join(folder, filepath.Base(string(fileName)))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting %s uid=%d, gid=%d, %s, %s to %s\n", os.FileMode(e.Perms), e.Uid, e.Gid, humanize.Bytes(uint64(e.FileSize)), fileName, fname))
				err = ioutil.WriteFile(fname, fileBytes, 0644)
				if err != nil {
					return false, err
				}
				return true, nil
			}
		} else {
			rr.Seek(int64(e.FileSize), io.SeekCurrent)
		}
	}

	return false, nil
}
