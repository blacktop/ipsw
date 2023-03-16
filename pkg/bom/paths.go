package bom

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
)

const (
	TypeBad     = 0
	TypeFile    = 1
	TypeDir     = 2
	TypeSymLink = 3
	TypeDevice  = 4
	TypeSocket  = 5
)

const (
	ArchNone  = 0
	ArchMachO = 1
	ArchFat   = 2
	ArchCFM   = 3
)

const (
	CompressionNone = 0
	CompressionZlib = 1
	CompressionBZ2  = 2
	CompressionAuto = 8
	CompressionMask = 0xF
)

type pathInfo struct {
	ID    uint32
	Index uint32
}

type pathDetail struct {
	Type         uint8
	_            uint8 // unknown
	Architecture uint16
	Mode         uint16
	User         uint32
	Group        uint32
	ModTime      uint32
	Size         uint32
	_            uint8 // unknown
	Checksum     uint32
	DevType      uint32
}

type File struct {
	id      int
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool

	parent int
}

func (b *File) Name() string {
	return b.name
}

func (b *File) Size() int64 {
	return b.size
}

func (b *File) Mode() os.FileMode {
	return b.mode
}

func (b *File) ModTime() time.Time {
	return b.modTime
}

func (b *File) IsDir() bool {
	return b.isDir
}

func (b *File) Sys() any {
	return nil
}

func (b *BOM) GetPaths() ([]os.FileInfo, error) {
	paths, err := b.ReadTree("Paths")
	if err != nil {
		return nil, err
	}

	fileInfo := make([]os.FileInfo, 0)
	parents := make(map[uint32]uint32)
	filepaths := make(map[uint32]string)

	for {
		for _, index := range paths.Indices {
			var pinfo pathInfo
			if err := binary.Read(index.ValueReader, binary.BigEndian, &pinfo); err != nil {
				log.Errorf("failed to read path info: %v", err)
			}

			var parent uint32
			if err := binary.Read(index.KeyReader, binary.BigEndian, &parent); err != nil {
				log.Errorf("failed to read path detail: %v", err)
			}

			name, err := readString(index.KeyReader)
			if err != nil {
				log.Errorf("failed to read path name: %v", err)
			}

			name = fmt.Sprint(string(name))

			var pdetail pathDetail
			if err := b.lookup(int(pinfo.Index), &pdetail); err != nil {
				return nil, err
			}

			if parent > 0 {
				parents[pinfo.ID] = parent
				filepaths[pinfo.ID] = name
			}

			for parentID := parent; parentID > 0; parentID = parents[parentID] {
				name = filepath.Join(filepaths[parentID], name)
			}

			f := &File{
				id:      int(pinfo.ID),
				name:    name,
				parent:  int(parent),
				mode:    os.FileMode(pdetail.Mode),
				isDir:   pdetail.Type == TypeDir,
				modTime: time.Unix(int64(pdetail.ModTime), 0),
				size:    int64(pdetail.Size),
			}

			fileInfo = append(fileInfo, f)
		}

		if paths.Forward == 0 {
			break
		} else {
			paths, err = b.readTree(paths.Forward)
			if err != nil {
				return nil, err
			}
			paths.Indices = make([]TreeIndex, paths.Count)
			for i := uint16(0); i < paths.Count; i++ {
				var ti TreeIndex
				if err := binary.Read(paths.r, binary.BigEndian, &ti.Value); err != nil {
					return nil, err
				}
				if err := binary.Read(paths.r, binary.BigEndian, &ti.Key); err != nil {
					return nil, err
				}
				ti.KeyReader, err = b.blockReader(ti.Key)
				if err != nil {
					return nil, err
				}
				ti.ValueReader, err = b.blockReader(ti.Value)
				if err != nil {
					return nil, err
				}
				paths.Indices[i] = ti
			}
		}
	}

	return fileInfo, nil
}

func readString(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		return strings.Trim(scanner.Text(), "\x00"), nil
	}
	return "", scanner.Err()
}
