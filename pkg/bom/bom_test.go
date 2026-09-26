package bom

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

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
