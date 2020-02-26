/*
  Golang implementation of bomutils <https://github.com/hogliux/bomutils>

  Copyright (C) 2013 Fabian Renn - fabian.renn (at) gmail.com

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA  02110-1301 USA.

  Initial work done by Joseph Coffland. Further contributions by Julian Devlin.
  Numerous further improvements by Baron Roberts.

  Golang translation by Callum Jones cj (at) icj (dot) me
*/

package bom

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BOMHeader struct {
	Magic          [8]byte
	Version        uint32
	NumberOfBlocks uint32
	IndexOffset    uint32
	IndexLength    uint32
	VarsOffset     uint32
	VarsLength     uint32
}

type BOMPointer struct {
	Address uint32
	Length  uint32
}

type blockPointers []BOMPointer

func (bp blockPointers) lookup(r io.ReadSeeker, i int, into interface{}) error {
	elem := bp[i]

	if _, err := r.Seek(int64(elem.Address), 0); err != nil {
		return err
	}

	if err := binary.Read(r, binary.BigEndian, into); err != nil {
		return err
	}

	return nil
}

type tree struct {
	Tree      [4]byte // 'tree'
	Version   uint32
	Child     uint32
	BlockSize uint32
	PathCount uint32
	Unknown   uint8
}

type paths struct {
	IsLeaf   uint16
	Count    uint16
	Forward  uint32
	Backward uint32
}

type pathIndices struct {
	Index0 uint32
	Index1 uint32
}

type pathInfo1 struct {
	ID    uint32
	Index uint32
}

type pathInfo2 struct {
	Type           uint8
	_              uint8 // unknown
	Architecture   uint16
	Mode           uint16
	User           uint32
	Group          uint32
	ModTime        uint32
	Size           uint32
	_              uint8 // unknown
	Checksum       uint32
	DevType        uint32
	LinkNameLength uint32
}

var ErrInvalidFormat = errors.New("bom: invalid format")

// Read returns os.FileInfo from an io.Reader
func Read(r io.ReaderAt) ([]os.FileInfo, error) {
	var header BOMHeader
	br := io.NewSectionReader(r, 0, 1<<63-1)
	if err := binary.Read(br, binary.BigEndian, &header); err != nil {
		return nil, err
	}

	if string(header.Magic[0:]) != "BOMStore" {
		return nil, ErrInvalidFormat
	}

	if _, err := br.Seek(int64(header.IndexOffset), io.SeekStart); err != nil {
		return nil, err
	}

	var numBlockTablePointers uint32

	if err := binary.Read(br, binary.BigEndian, &numBlockTablePointers); err != nil {
		return nil, err
	}

	blockPointers := make(blockPointers, numBlockTablePointers)

	if err := binary.Read(br, binary.BigEndian, &blockPointers); err != nil {
		return nil, err
	}

	if _, err := br.Seek(int64(header.VarsOffset), 0); err != nil {
		return nil, err
	}

	var numVars uint32

	if err := binary.Read(br, binary.BigEndian, &numVars); err != nil {
		return nil, err
	}

	fileInfo := make([]os.FileInfo, 0)

	for i := 0; i < int(numVars); i++ {
		var index uint32
		var length uint8

		if err := binary.Read(br, binary.BigEndian, &index); err != nil {
			return nil, err
		}

		if err := binary.Read(br, binary.BigEndian, &length); err != nil {
			return nil, err
		}

		name := make([]byte, length)

		if err := binary.Read(br, binary.BigEndian, &name); err != nil {
			return nil, err
		}

		if strings.Contains(string(name[:]), "Paths") {
			var tree tree

			if err := blockPointers.lookup(br, int(index), &tree); err != nil {
				return nil, err
			}

			var paths paths

			if err := blockPointers.lookup(br, int(tree.Child), &paths); err != nil {
				return nil, err
			}

			indices := make([]pathIndices, paths.Count)

			if err := binary.Read(br, binary.BigEndian, &indices); err != nil {
				return nil, err
			}

			for paths.IsLeaf == 0 {
				if err := blockPointers.lookup(br, int(indices[0].Index0), &paths); err != nil {
					return nil, err
				}

				indices = make([]pathIndices, paths.Count)

				if err := binary.Read(br, binary.BigEndian, &indices); err != nil {
					return nil, err
				}
			}

			parents := make(map[uint32]uint32)
			filepaths := make(map[uint32]string)

			for {
				for j := 0; j < int(paths.Count); j++ {
					index0 := indices[j].Index0
					index1 := indices[j].Index1

					var parent uint32

					if err := blockPointers.lookup(br, int(index1), &parent); err != nil {
						return nil, err
					}

					name, err := readString(br)

					if err != nil {
						return nil, err
					}

					var pathInfo1 pathInfo1

					if err := blockPointers.lookup(br, int(index0), &pathInfo1); err != nil {
						return nil, err
					}

					var pathInfo2 pathInfo2

					if err := blockPointers.lookup(br, int(pathInfo1.Index), &pathInfo2); err != nil {
						return nil, err
					}

					if parent > 0 {
						parents[pathInfo1.ID] = parent
						filepaths[pathInfo1.ID] = name
					}

					for parentID := parent; parentID > 0; parentID = parents[parentID] {
						name = filepath.Join(filepaths[parentID], name)
					}

					f := &bomFile{
						id:      int(pathInfo1.ID),
						name:    name,
						parent:  int(parent),
						mode:    os.FileMode(pathInfo2.Mode),
						isDir:   pathInfo2.Type == TypeDir,
						modTime: time.Unix(int64(pathInfo2.ModTime), 0),
						size:    int64(pathInfo2.Size),
					}

					fileInfo = append(fileInfo, f)
				}

				if paths.Forward == 0 {
					break
				} else {
					err := blockPointers.lookup(br, int(paths.Forward), &paths)

					if err != nil {
						return nil, err
					}

					indices = make([]pathIndices, paths.Count)

					if err := binary.Read(br, binary.BigEndian, &indices); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return fileInfo, nil
}

func readString(r io.Reader) (string, error) {
	var b byte
	var str string

	for {
		err := binary.Read(r, binary.BigEndian, &b)

		if err != nil {
			return str, err
		}

		if b == '\x00' {
			return str, nil
		}

		str += string(b)
	}
}

const (
	TypeFile = 1
	TypeDir  = 2
	TypeLink = 3
	TypeDev  = 4
)

type bomFile struct {
	id      int
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool

	parent int
}

func (b *bomFile) Name() string {
	return b.name
}

func (b *bomFile) Size() int64 {
	return b.size
}

func (b *bomFile) Mode() os.FileMode {
	return b.mode
}

func (b *bomFile) ModTime() time.Time {
	return b.modTime
}

func (b *bomFile) IsDir() bool {
	return b.isDir
}

func (b *bomFile) Sys() interface{} {
	return nil
}
