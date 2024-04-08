package fw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/commands/img4"
)

const RTKitMagic = "rkosftab"

type RTKitHeader struct {
	_        [32]byte
	Magic    [8]byte // "rkosftab"
	NumBlobs uint32
	_        uint32
}

type RTKitBlob struct {
	Name   [4]byte
	Offset uint32
	Size   uint32
	_      uint32
}

func SplitGpuFW(in, folder string) ([]string, error) {
	var out []string

	dat, err := os.ReadFile(in)
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(dat)

	var hdr RTKitHeader
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}

	if string(hdr.Magic[:]) != RTKitMagic {
		if !bytes.Contains(dat[:16], []byte("IM4P")) {
			return nil, fmt.Errorf("invalid RTKit header magic: %s; input file might be an im4p (extract via `ipsw img4 extract` first)", string(hdr.Magic[:]))
		}
		tmpDir, err := os.MkdirTemp(os.TempDir(), "gpu")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmpDir)
		infile := filepath.Join(tmpDir, filepath.Clean(in)+".payload")
		log.Warn("IM4P header detected, extracting payload")
		if err := img4.ExtractPayload(filepath.Clean(in), infile, false); err != nil {
			return nil, err
		}
		// reread the extracted file
		dat, err = os.ReadFile(infile)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(dat)
		if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
			return nil, err
		}
	}

	blobs := make([]RTKitBlob, hdr.NumBlobs)
	if err := binary.Read(r, binary.LittleEndian, &blobs); err != nil {
		return nil, err
	}

	for _, blob := range blobs {
		r.Seek(int64(blob.Offset), 0)
		buf := make([]byte, blob.Size)
		if _, err := r.Read(buf); err != nil {
			return nil, err
		}

		fname := string(blob.Name[:]) + ".bin"
		if len(folder) > 0 {
			if err := os.MkdirAll(folder, 0o750); err != nil {
				return nil, err
			}
			fname = filepath.Join(folder, fname)
		}
		log.WithFields(log.Fields{
			"name":   string(blob.Name[:]),
			"size":   fmt.Sprintf("%#x", blob.Size),
			"offset": fmt.Sprintf("%#x", blob.Offset),
		}).Info("Extracting")
		if err := os.WriteFile(fname, buf, 0o644); err != nil {
			return nil, err
		}
		out = append(out, fname)
	}

	return out, nil
}
