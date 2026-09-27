package bom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestReadTreesInlineKeysAcrossLeaves(t *testing.T) {
	var data bytes.Buffer
	b := &BOM{Vars: []Var{{Name: "BITMAPKEYS"}}}
	add := func(value any) {
		start := data.Len()
		if err := binary.Write(&data, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
		b.BlockTable.BlockPointers = append(b.BlockTable.BlockPointers,
			Pointer{Address: uint32(start), Length: uint32(data.Len() - start)})
	}
	add(TreeHeader{Magic: [4]byte{'t', 'r', 'e', 'e'}, Child: 1})
	// Each leaf contains one inline key and one block-backed key. Inline values
	// deliberately exceed the block table so they cannot resolve as pointers.
	add([7]uint32{1<<16 | 2, 2, 0, 4, 0x11223344, 4, 3})
	add([7]uint32{1<<16 | 2, 0, 1, 5, 0x55667788, 5, 3})
	add([]byte("key"))
	add([]byte{0xa0})
	add([]byte{0xa1})
	b.r = bytes.NewReader(data.Bytes())
	check := func(tree *Tree, leaf int) {
		t.Helper()
		if len(tree.Indices) != 2 {
			t.Fatalf("leaf %d: got %d indices", leaf, len(tree.Indices))
		}
		inline := []uint32{0x11223344, 0x55667788}[leaf]
		for i, index := range tree.Indices {
			want := []byte("key")
			if i == 0 {
				want = binary.BigEndian.AppendUint32(nil, inline)
			}
			key, err := io.ReadAll(index.KeyReader)
			if err != nil || !bytes.Equal(key, want) {
				t.Fatalf("leaf %d key %d = %x, %v; want %x", leaf, i, key, err, want)
			}
			value, err := io.ReadAll(index.ValueReader)
			if err != nil || !bytes.Equal(value, []byte{0xa0 + byte(leaf)}) {
				t.Fatalf("leaf %d value %d = %x, %v", leaf, i, value, err)
			}
		}
	}
	first, err := b.ReadTree("BITMAPKEYS")
	if err != nil {
		t.Fatal(err)
	}
	check(first, 0)
	trees, err := b.ReadTrees("BITMAPKEYS")
	if err != nil || len(trees) != 2 {
		t.Fatalf("ReadTrees: got %d leaves, %v", len(trees), err)
	}
	for i, tree := range trees {
		check(tree, i)
	}
	// Missing values must remain errors; only keys have an inline fallback.
	for _, leaf := range []int{1, 2} {
		corrupt := bytes.Clone(data.Bytes())
		start := b.BlockTable.BlockPointers[leaf].Address
		binary.BigEndian.PutUint32(corrupt[start+12:], 0xffffffff)
		b.r = bytes.NewReader(corrupt)
		if _, err := b.ReadTrees("BITMAPKEYS"); !errors.Is(err, ErrBlockNotFound) {
			t.Fatalf("leaf %d: missing value was accepted: %v", leaf, err)
		}
	}
}

func TestTreeTraversalCycles(t *testing.T) {
	for _, tc := range []struct {
		name     string
		children bool
		links    []uint32
		invalid  bool
	}{
		{"leaves", false, []uint32{2, 0}, false},
		{"forward self", false, []uint32{1}, true},
		{"forward pair", false, []uint32{2, 1}, true},
		{"child self", true, []uint32{1}, true},
		{"child pair", true, []uint32{2, 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data bytes.Buffer
			b := &BOM{Vars: []Var{{Name: "Paths"}}}
			add := func(value any) {
				start := data.Len()
				if err := binary.Write(&data, binary.BigEndian, value); err != nil {
					t.Fatal(err)
				}
				b.BlockTable.BlockPointers = append(b.BlockTable.BlockPointers,
					Pointer{Address: uint32(start), Length: uint32(data.Len() - start)})
			}
			add(TreeHeader{Magic: [4]byte{'t', 'r', 'e', 'e'}, Child: 1})
			for _, link := range tc.links {
				if tc.children {
					add([5]uint32{1, 0, 0, link, 0}) // Internal node, one child.
				} else {
					add([3]uint32{1 << 16, link, 0}) // Empty leaf with a forward link.
				}
			}
			b.r = bytes.NewReader(data.Bytes())
			_, err := b.ReadTrees("Paths")
			if errors.Is(err, ErrInvalidFormat) != tc.invalid || (!tc.invalid && err != nil) {
				t.Fatalf("ReadTrees = %v", err)
			}
			if tc.children {
				if _, err := b.ReadTree("Paths"); !errors.Is(err, ErrInvalidFormat) {
					t.Fatalf("ReadTree = %v", err)
				}
			}
			if _, err := b.GetPaths(); errors.Is(err, ErrInvalidFormat) != tc.invalid {
				t.Fatalf("GetPaths = %v", err)
			}
		})
	}
}
