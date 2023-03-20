package bom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const magic = "BOMStore"

type BOM struct {
	Header     header
	BlockTable blockTable
	Vars       []Var

	r io.ReaderAt
}

type header struct {
	Magic          [8]byte
	Version        uint32
	NumberOfBlocks uint32
	IndexOffset    uint32
	IndexLength    uint32
	VarsOffset     uint32
	VarsLength     uint32
}

type Pointer struct {
	Address uint32
	Length  uint32
}

type blockTable struct {
	NumberOfBlockTablePointers uint32
	BlockPointers              []Pointer
}

func (b *BOM) lookup(i int, into any) error {
	elem := b.BlockTable.BlockPointers[i]
	if err := binary.Read(io.NewSectionReader(b.r, int64(elem.Address), int64(elem.Length)), binary.BigEndian, into); err != nil {
		return fmt.Errorf("failed to lookup objct at index %d: %v", i, err)
	}
	return nil
}

type Var struct {
	BlockTableIndex uint32
	NameLength      uint8
	Name            string
}

type TreeHeader struct {
	Magic     [4]byte // 'tree'
	Version   uint32
	Child     uint32
	BlockSize uint32
	PathCount uint32
	Unknown   uint8
}

type TreeIndex struct {
	Value uint32
	Key   uint32

	KeyReader   io.Reader
	ValueReader io.Reader
}

type Tree struct {
	IsLeaf   uint16
	Count    uint16
	Forward  uint32
	Backward uint32
	Indices  []TreeIndex

	r io.Reader
}

func (t *Tree) Reader() io.Reader {
	return t.r
}

var ErrInvalidFormat = errors.New("bom: invalid format")
var ErrBlockNotFound = errors.New("bom: block not found")

func New(r io.ReaderAt) (*BOM, error) {
	bom := &BOM{r: r}

	br := io.NewSectionReader(r, 0, 1<<63-1)

	if err := binary.Read(br, binary.BigEndian, &bom.Header); err != nil {
		return nil, err
	}

	if string(bom.Header.Magic[0:]) != magic {
		return nil, ErrInvalidFormat
	}

	if _, err := br.Seek(int64(bom.Header.IndexOffset), io.SeekStart); err != nil {
		return nil, err
	}

	if err := binary.Read(br, binary.BigEndian, &bom.BlockTable.NumberOfBlockTablePointers); err != nil {
		return nil, err
	}
	bom.BlockTable.BlockPointers = make([]Pointer, bom.BlockTable.NumberOfBlockTablePointers)
	if err := binary.Read(br, binary.BigEndian, &bom.BlockTable.BlockPointers); err != nil {
		return nil, err
	}

	if _, err := br.Seek(int64(bom.Header.VarsOffset), 0); err != nil {
		return nil, err
	}

	var numVars uint32
	if err := binary.Read(br, binary.BigEndian, &numVars); err != nil {
		return nil, err
	}

	bom.Vars = make([]Var, numVars)

	for i := uint32(0); i < numVars; i++ {
		var v Var
		if err := binary.Read(br, binary.BigEndian, &v.BlockTableIndex); err != nil {
			return nil, err
		}
		if err := binary.Read(br, binary.BigEndian, &v.NameLength); err != nil {
			return nil, err
		}
		name := make([]byte, v.NameLength)
		if err := binary.Read(br, binary.BigEndian, &name); err != nil {
			return nil, err
		}
		v.Name = string(bytes.Trim(name, "\x00"))
		bom.Vars[i] = v
	}

	return bom, nil
}

func (b *BOM) ReadBlock(name string) (io.Reader, error) {
	for _, v := range b.Vars {

		if v.Name != name {
			continue
		}

		b, err := b.blockReader(v.BlockTableIndex)
		if err != nil {
			return nil, err
		}
		return b, nil
	}

	return nil, fmt.Errorf("bom: block %q not found", name)
}

func (b *BOM) blockReader(index uint32) (io.Reader, error) {
	if index >= uint32(len(b.BlockTable.BlockPointers)) {
		return nil, ErrBlockNotFound
	}
	p := b.BlockTable.BlockPointers[index]
	return io.NewSectionReader(b.r, int64(p.Address), int64(p.Length)), nil
}

func (b *BOM) BlockNames() []string {
	names := make([]string, len(b.Vars))
	for i, v := range b.Vars {
		names[i] = v.Name
	}
	return names
}

func (b *BOM) ReadTree(name string) (*Tree, error) {
	br, err := b.ReadBlock(name)
	if err != nil {
		return nil, err
	}

	var thead TreeHeader
	if err := binary.Read(br, binary.BigEndian, &thead); err != nil {
		return nil, err
	}

	tree, err := b.readTree(thead.Child)
	if err != nil {
		return nil, err
	}

	for tree.IsLeaf == 0 {
		var ti TreeIndex
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Value); err != nil {
			return nil, err
		}
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Key); err != nil {
			return nil, err
		}

		tree, err = b.readTree(ti.Value)
		if err != nil {
			return nil, err
		}
	}

	tree.Indices = make([]TreeIndex, tree.Count)

	for i := uint16(0); i < tree.Count; i++ {
		var ti TreeIndex
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Value); err != nil {
			return nil, err
		}
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Key); err != nil {
			return nil, err
		}
		ti.KeyReader, err = b.blockReader(ti.Key)
		if err != nil {
			if errors.Is(err, ErrBlockNotFound) {
				p := make([]byte, 4)
				binary.BigEndian.PutUint32(p, ti.Key)
				ti.KeyReader = bytes.NewBuffer(p)
			} else {
				return nil, err
			}
		}
		ti.ValueReader, err = b.blockReader(ti.Value)
		if err != nil {
			return nil, err
		}
		tree.Indices[i] = ti
	}

	return tree, nil
}

func (b *BOM) ReadTrees(name string) ([]*Tree, error) {
	var trees []*Tree

	br, err := b.ReadBlock(name)
	if err != nil {
		return nil, err
	}

	var thead TreeHeader
	if err := binary.Read(br, binary.BigEndian, &thead); err != nil {
		return nil, err
	}

	tree, err := b.readTree(thead.Child)
	if err != nil {
		return nil, err
	}

	for tree.IsLeaf == 0 {
		var ti TreeIndex
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Value); err != nil {
			return nil, err
		}
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Key); err != nil {
			return nil, err
		}

		tree, err = b.readTree(ti.Value)
		if err != nil {
			return nil, err
		}
	}

	tree.Indices = make([]TreeIndex, tree.Count)

	for i := uint16(0); i < tree.Count; i++ {
		var ti TreeIndex
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Value); err != nil {
			return nil, err
		}
		if err := binary.Read(tree.r, binary.BigEndian, &ti.Key); err != nil {
			return nil, err
		}
		ti.KeyReader, err = b.blockReader(ti.Key)
		if err != nil {
			if errors.Is(err, ErrBlockNotFound) {
				p := make([]byte, 4)
				binary.BigEndian.PutUint32(p, ti.Key)
				ti.KeyReader = bytes.NewBuffer(p)
			} else {
				return nil, err
			}
		}
		ti.ValueReader, err = b.blockReader(ti.Value)
		if err != nil {
			return nil, err
		}
		tree.Indices[i] = ti
	}

	trees = append(trees, tree)

	for {
		if tree.Forward == 0 {
			break
		} else {
			tree, err = b.readTree(tree.Forward)
			if err != nil {
				return nil, err
			}
			tree.Indices = make([]TreeIndex, tree.Count)
			for i := uint16(0); i < tree.Count; i++ {
				var ti TreeIndex
				if err := binary.Read(tree.r, binary.BigEndian, &ti.Value); err != nil {
					return nil, err
				}
				if err := binary.Read(tree.r, binary.BigEndian, &ti.Key); err != nil {
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
				tree.Indices[i] = ti
			}
			trees = append(trees, tree)
		}
	}

	return trees, nil
}

func (b *BOM) readTree(index uint32) (*Tree, error) {
	buf, err := b.blockReader(index)
	if err != nil {
		return nil, err
	}
	tree := Tree{r: buf}
	if err := binary.Read(buf, binary.BigEndian, &tree.IsLeaf); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &tree.Count); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &tree.Forward); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &tree.Backward); err != nil {
		return nil, err
	}
	return &tree, nil
}
