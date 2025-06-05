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
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
	"github.com/dustin/go-humanize"
	"github.com/pkg/errors"
	"github.com/ulikunitz/xz"
	"golang.org/x/sys/execabs"
	// "github.com/blacktop/xz"
	// "github.com/therootcompany/xz"
)

const (
	pbzxMagic       = 0x70627a78 // "pbzx"
	MagicYaa1Header = 0x31414159 // "YAA1"
	aa01Header      = 0x31304141 // "AA01"
	hasMoreChunks   = 0x800000
)

type pbzxHeader struct {
	Magic            uint32
	UncompressedSize uint64
}

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

// RemoteList lists the files in a remote ota payloads
func RemoteList(zr *zip.Reader) ([]os.FileInfo, error) {
	return parseBOMFromZip(zr, `post.bom$`)
}

// NewXZReader uses the xz command to extract the Apple Archives (xz streams) or falls back to the pure Golang xz decompression lib
func NewXZReader(r io.Reader) (io.ReadCloser, error) {
	if _, err := execabs.LookPath("xz"); err != nil {
		xr, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(xr), nil
	}

	rpipe, wpipe := io.Pipe()
	var errb bytes.Buffer
	cmd := execabs.Command("xz", "--decompress", "--stdout")
	cmd.Stdin = r
	cmd.Stdout = wpipe
	cmd.Stderr = &errb
	go func() {
		err := cmd.Run()
		if err != nil && errb.Len() != 0 {
			err = errors.New(strings.TrimRight(errb.String(), "\r\n"))
		}
		wpipe.CloseWithError(err)
	}()
	return rpipe, nil
}

func parseBOMFromZip(zr *zip.Reader, bomPathPattern string) ([]os.FileInfo, error) {
	var validPostBOM = regexp.MustCompile(bomPathPattern)

	for _, f := range zr.File {
		if validPostBOM.MatchString(f.Name) {
			r, err := f.Open()
			if err != nil {
				return nil, errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
			}
			bomData := make([]byte, f.UncompressedSize64)
			io.ReadFull(r, bomData)
			r.Close()
			bm, err := bom.New(bytes.NewReader(bomData))
			if err != nil {
				return nil, fmt.Errorf("failed to parse bom: %v", err)
			}
			return bm.GetPaths()
		}
	}

	return nil, fmt.Errorf("post.bom not found in zip")
}

// RemoteExtract extracts and decompresses remote OTA payload files
func RemoteExtract(zr *zip.Reader, extractPattern, destPath string, shouldStop func(string) bool) ([]string, error) {
	var outfiles []string
	var validPayload = regexp.MustCompile(`payload.0\d+$`)

	// sortFileBySize(zr.File)
	// sortFileByNameAscend(zr.File)

	found := false
	for _, f := range zr.File {
		if validPayload.MatchString(f.Name) {
			utils.Indent(log.WithFields(log.Fields{
				"filename": f.Name,
				"size":     humanize.Bytes(f.UncompressedSize64),
			}).Debug, 2)("Processing OTA payload")
			goteet, path, err := Parse(f, destPath, extractPattern)
			if err != nil {
				log.Error(err.Error())
			}
			if goteet {
				outfiles = append(outfiles, path)
				found = true
				if shouldStop(path) {
					return outfiles, nil
				}
			}
		}
	}
	if found {
		return outfiles, nil
	}
	return nil, fmt.Errorf("%s not found", extractPattern)
}

// Parse parses a ota payload file inside the zip
func Parse(payload *zip.File, folder, extractPattern string) (bool, string, error) {

	// This is the FAST path that execs the 'aa' binary if found on macOS
	if aaPath, err := execabs.LookPath("aa"); err == nil {
		// make tmp folder
		dir, err := os.MkdirTemp("", "ota_"+filepath.Base(payload.Name))
		if err != nil {
			return false, "", fmt.Errorf("failed to create tmp folder: %v", err)
		}
		defer os.RemoveAll(dir)

		rc, err := payload.Open()
		if err != nil {
			return false, "", fmt.Errorf("failed to open file in zip %s: %v", payload.Name, err)
		}
		defer rc.Close()

		var errb bytes.Buffer
		cmd := execabs.Command(aaPath, "extract", "-d", dir, "-include-regex", extractPattern)
		cmd.Stdin = rc
		err = cmd.Run()
		if err != nil && errb.Len() != 0 {
			err = errors.New(strings.TrimRight(errb.String(), "\r\n"))
			return false, "", err
		}

		// Is folder empty
		ff, err := os.ReadDir(dir)
		if err != nil {
			return false, "", fmt.Errorf("failed to create tmp folder: %v", err)
		}
		if len(ff) == 0 {
			return false, "", nil
		}

		var fname string
		err = filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !f.IsDir() {
				fname = filepath.Join(folder, filepath.Clean(strings.TrimPrefix(path, dir)))
				if err := os.MkdirAll(filepath.Dir(fname), 0750); err != nil {
					return fmt.Errorf("failed to create dir %s: %v", filepath.Dir(fname), err)
				}
				utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting %s\t%s\t%s", f.Mode(), humanize.Bytes(uint64(f.Size())), fname))
				if err := os.Rename(path, fname); err != nil {
					return fmt.Errorf("failed to mv file %s to %s: %v", strings.TrimPrefix(path, dir), fname, err)
				}
			}
			return nil
		})
		if err != nil {
			return false, "", fmt.Errorf("failed to read files in tmp folder: %v", err)
		}

		return true, fname, nil
	}

	pData := make([]byte, payload.UncompressedSize64)

	rc, err := payload.Open()
	if err != nil {
		return false, "", errors.Wrapf(err, "failed to open file in zip: %s", payload.Name)
	}

	io.ReadFull(rc, pData)
	rc.Close()

	pr := bytes.NewReader(pData)

	var pbzx pbzxHeader
	if err := binary.Read(pr, binary.BigEndian, &pbzx); err != nil {
		return false, "", err
	}

	if pbzx.Magic != pbzxMagic {
		return false, "", errors.New("src not a pbzx stream")
	}

	xzBuf := new(bytes.Buffer)

	for {
		var xzTag xzHeader
		if err := binary.Read(pr, binary.BigEndian, &xzTag); err != nil {
			return false, "", err
		}

		xzChunkBuf := make([]byte, xzTag.Size)
		if err := binary.Read(pr, binary.BigEndian, &xzChunkBuf); err != nil {
			return false, "", err
		}

		// xr, err := xz.NewReader(bytes.NewReader(xzChunkBuf))
		// xr, err := xz.NewReader(bytes.NewReader(xzChunkBuf), 0)
		xr, err := NewXZReader(bytes.NewReader(xzChunkBuf))
		if err != nil {
			return false, "", err
		}
		defer xr.Close()

		io.Copy(xzBuf, xr)

		if (xzTag.Flags & hasMoreChunks) == 0 {
			break
		}
	}

	rr := bytes.NewReader(xzBuf.Bytes())

	aa := &yaa.YAA{}
	if err = aa.Parse(rr); err != nil {
		if !errors.Is(err, yaa.ErrInvalidMagic) {
			return false, "", err
		}
		for {
			// pre iOS14.x OTA file
			var e entry
			if err := binary.Read(rr, binary.BigEndian, &e); err != nil {
				if err == io.EOF {
					break
				}
				return false, "", err
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
				return false, "", err
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

			// FIXME: need to figure out how to support OLD OTAs as well
			// ent.Mod = os.FileMode(e.Perms)
			// ent.Path = string(fileName)
			// ent.Size = uint32(e.FileSize)
		}
	}

	if len(extractPattern) > 0 {
		for _, ent := range aa.Entries {
			match, _ := regexp.MatchString(extractPattern, ent.Path)
			if match || strings.Contains(strings.ToLower(string(ent.Path)), strings.ToLower(extractPattern)) {
				fileBytes := make([]byte, ent.Size)
				if err := binary.Read(rr, binary.LittleEndian, &fileBytes); err != nil {
					if err == io.EOF {
						break
					}
					return false, "", err
				}

				if err := os.MkdirAll(folder, 0750); err != nil {
					return false, "", fmt.Errorf("failed to create folder: %s", folder)
				}
				fname := filepath.Join(folder, filepath.Clean(ent.Path))
				utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting %s uid=%d, gid=%d, %s, %s", ent.Mod, ent.Uid, ent.Gid, humanize.Bytes(uint64(ent.Size)), fname))
				if err := os.WriteFile(fname, fileBytes, 0660); err != nil {
					return false, "", err
				}

				return true, fname, nil
			}
		}
	}

	return false, "", nil
}
