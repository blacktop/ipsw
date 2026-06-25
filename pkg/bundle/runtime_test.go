package bundle

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// segSpec describes a synthetic LC_SEGMENT_64 for a header-only test Mach-O.
type segSpec struct {
	name    string
	vmSize  uint64
	fileOff uint64
	fileSz  uint64
}

// buildHeaderMachO builds a header-only mach_header_64 + load commands (the form
// stored in a DNUB "nold" directory). When symtab is true an LC_SYMTAB with
// non-zero offsets is appended so the test can assert it gets zeroed.
func buildHeaderMachO(segs []segSpec, symtab bool) []byte {
	le := binary.LittleEndian
	var cmds []byte
	for _, s := range segs {
		c := make([]byte, 0x48) // LC_SEGMENT_64, no sections
		le.PutUint32(c[0:], 0x19)
		le.PutUint32(c[4:], 0x48)
		copy(c[8:24], s.name)
		le.PutUint64(c[32:], s.vmSize)  // vmsize
		le.PutUint64(c[40:], s.fileOff) // fileoff
		le.PutUint64(c[48:], s.fileSz)  // filesz
		cmds = append(cmds, c...)
	}
	ncmds := len(segs)
	if symtab {
		c := make([]byte, 0x18) // LC_SYMTAB
		le.PutUint32(c[0:], 0x02)
		le.PutUint32(c[4:], 0x18)
		le.PutUint32(c[8:], 0xdeadbeef)  // symoff -> must be zeroed
		le.PutUint32(c[12:], 0x11)       // nsyms -> must be zeroed
		le.PutUint32(c[16:], 0xcafef00d) // stroff -> must be zeroed
		le.PutUint32(c[20:], 0x22)       // strsize -> must be zeroed
		cmds = append(cmds, c...)
		ncmds++
	}
	hdr := make([]byte, 0x20) // mach_header_64
	le.PutUint32(hdr[0:], 0xFEEDFACF)
	le.PutUint32(hdr[16:], uint32(ncmds))
	le.PutUint32(hdr[20:], uint32(len(cmds)))
	return append(hdr, cmds...)
}

// synthBundle assembles a minimal Type-4 (DNUB) Bundle whose nold/rtxt/rdat
// ranges point at the supplied header, __TEXT bytes and trailing bytes.
func synthBundle(hdr, textBytes, dataBytes []byte) *Bundle {
	noldOff := uint64(0x100)
	rtxtOff := noldOff + uint64(len(hdr)) + 0x10
	rdatOff := rtxtOff + uint64(len(textBytes)) + 0x10
	blob := make([]byte, rdatOff+uint64(len(dataBytes)))
	copy(blob[noldOff:], hdr)
	copy(blob[rtxtOff:], textBytes)
	copy(blob[rdatOff:], dataBytes)

	// typ4Range.NameString reverses the stored 4cc, so store the reversed form.
	mkRange := func(name string, off, sz uint64) typ4Range {
		rev := []byte(name)
		for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
			rev[i], rev[j] = rev[j], rev[i]
		}
		var r typ4Range
		copy(r.Name[:], rev)
		r.Offset = off
		r.Size = sz
		return r
	}
	var t4 Type4
	t4.Ranges[0] = mkRange("rtxt", rtxtOff, uint64(len(textBytes)))
	t4.Ranges[1] = mkRange("rdat", rdatOff, uint64(len(dataBytes)))
	t4.Ranges[2] = mkRange("nold", noldOff, uint64(len(hdr)))
	return &Bundle{Header: Header{Type: 4}, TypeHeader: t4, r: bytes.NewReader(blob)}
}

func allBytesEqual(b []byte, v byte) bool {
	for _, x := range b {
		if x != v {
			return false
		}
	}
	return true
}

// TestExtractRuntimeMachO covers the normal reconstruction: header from nold,
// __TEXT from rtxt, the remainder from rdat, with LC_SYMTAB zeroed.
func TestExtractRuntimeMachO(t *testing.T) {
	hdr := buildHeaderMachO([]segSpec{
		{name: "__TEXT", vmSize: 0x100, fileOff: 0x100, fileSz: 0x40},
		{name: "__DATA", vmSize: 0x40, fileOff: 0x140, fileSz: 0x40},
	}, true)
	textBytes := bytes.Repeat([]byte{0xAA}, 0x40)
	dataBytes := bytes.Repeat([]byte{0xBB}, 0x40)

	out, err := synthBundle(hdr, textBytes, dataBytes).ExtractRuntimeMachO()
	if err != nil {
		t.Fatalf("ExtractRuntimeMachO: %v", err)
	}
	if len(out) != 0x180 {
		t.Fatalf("output size = 0x%x, want 0x180", len(out))
	}
	if binary.LittleEndian.Uint32(out[:4]) != 0xFEEDFACF {
		t.Fatalf("output does not start with MH_MAGIC_64: %x", out[:4])
	}
	if !allBytesEqual(out[0x100:0x140], 0xAA) {
		t.Errorf("__TEXT not sourced from rtxt blob")
	}
	if !allBytesEqual(out[0x140:0x180], 0xBB) {
		t.Errorf("trailing segment not sourced from rdat blob")
	}
	if !allBytesEqual(out[len(hdr):0x100], 0x00) {
		t.Errorf("padding between header and __TEXT is not zero")
	}
	// LC_SYMTAB body (symoff..strsize) is the last 16 bytes of the header.
	if !allBytesEqual(out[len(hdr)-16:len(hdr)], 0x00) {
		t.Errorf("LC_SYMTAB offsets were not zeroed: %x", out[len(hdr)-16:len(hdr)])
	}
}

// TestExtractRuntimeMachOPreservesHeader guards the case where __TEXT.fileoff
// falls inside the header range (e.g. 0): the rtxt copy must not clobber the
// MH_MAGIC_64 / load commands. Before the header was written last this produced
// a non-parseable Mach-O.
func TestExtractRuntimeMachOPreservesHeader(t *testing.T) {
	hdr := buildHeaderMachO([]segSpec{
		{name: "__TEXT", vmSize: 0x100, fileOff: 0, fileSz: 0x100},
	}, false)
	textBytes := bytes.Repeat([]byte{0xAA}, 0x100)

	out, err := synthBundle(hdr, textBytes, nil).ExtractRuntimeMachO()
	if err != nil {
		t.Fatalf("ExtractRuntimeMachO: %v", err)
	}
	if binary.LittleEndian.Uint32(out[:4]) != 0xFEEDFACF {
		t.Fatalf("header was overwritten by __TEXT data: %x", out[:4])
	}
	if !bytes.Equal(out[:len(hdr)], hdr) {
		t.Errorf("header/load commands not preserved")
	}
	if !allBytesEqual(out[len(hdr):], 0xAA) {
		t.Errorf("__TEXT bytes after the header were not sourced from rtxt")
	}
}
