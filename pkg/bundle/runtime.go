package bundle

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	mhMagic64    = 0xFEEDFACF // MH_MAGIC_64
	lcSegment64  = 0x19       // LC_SEGMENT_64
	lcSymtab     = 0x02       // LC_SYMTAB
	lcDysymtab   = 0x0B       // LC_DYSYMTAB
	machoHdrSize = 0x20       // mach_header_64 size
	segment64Sz  = 0x48       // minimum LC_SEGMENT_64 command size (no sections)

	// mach_header_64 / load command field offsets (see <mach-o/loader.h>).
	hdrNcmdsOff   = 16 // mach_header_64.ncmds
	lcCmdSizeOff  = 4  // load_command.cmdsize
	lcHeaderSize  = 8  // sizeof(load_command): cmd (u32) + cmdsize (u32)
	lcBodyOff     = 8  // first command-specific field, after cmd+cmdsize
	symtabBodyEnd = 24 // end of symoff..strsize in symtab_command (4×u32 after the header)

	// segment_command_64 field offsets, relative to the command start.
	segNameOff   = 8  // segname[16]
	segNameLen   = 16 // sizeof(segname)
	segVMSizeOff = 32 // vmsize
	segFileOff   = 40 // fileoff
	segFileSzOff = 48 // filesz

	// maxOutputSize caps the reconstructed image to guard against a malformed
	// bundle declaring an absurd segment size that would exhaust memory. The
	// real DCP runtime image is ~15 MiB; 1 GiB is a generous ceiling.
	maxOutputSize = 1 << 30
)

// machoSegment describes the output file layout of a single LC_SEGMENT_64.
type machoSegment struct {
	fileOff uint64
	fileSz  uint64
}

// loadCmd locates a single load command within the bundle blob.
type loadCmd struct {
	cmd     uint32
	off     uint64 // absolute offset of the command within the bundle blob
	cmdSize uint32
}

// ExtractRuntimeMachO reconstructs the main DCP RTKit runtime Mach-O from a
// Type-4 (DNUB) bundle.
//
// The bundle stores the runtime image as a header-only Mach-O in the "nold"
// directory plus two concatenated segment blobs: "rtxt" holds __TEXT and "rdat"
// holds everything after it. This walks the nold directory, picks the image
// with the largest __TEXT (the main runtime image), and rehosts its segments at
// their original file offsets so the result loads at the correct vmaddr.
func (b *Bundle) ExtractRuntimeMachO() ([]byte, error) {
	t4, ok := b.TypeHeader.(Type4)
	if !ok {
		return nil, fmt.Errorf("bundle is not a Type-4 (DNUB) bundle: type=%d", b.Type)
	}

	rtxt, ok := t4.rangeByName("rtxt")
	if !ok {
		return nil, fmt.Errorf("bundle is missing 'rtxt' (__TEXT) range")
	}
	rdat, ok := t4.rangeByName("rdat")
	if !ok {
		return nil, fmt.Errorf("bundle is missing 'rdat' (__DATA) range")
	}
	nold, ok := t4.rangeByName("nold")
	if !ok {
		return nil, fmt.Errorf("bundle is missing 'nold' (Mach-O directory) range")
	}

	blob, err := b.readAll()
	if err != nil {
		return nil, err
	}

	moff, err := findRuntimeImage(blob, nold)
	if err != nil {
		return nil, err
	}

	return assembleRuntimeMachO(blob, moff, rtxt, rdat)
}

// readAll reads the entire bundle into memory via the backing reader.
func (b *Bundle) readAll() ([]byte, error) {
	if _, err := b.r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start of bundle: %v", err)
	}
	blob, err := io.ReadAll(b.r)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle: %v", err)
	}
	return blob, nil
}

// findRuntimeImage scans the nold directory for header-only Mach-Os and returns
// the offset of the one with the largest __TEXT vmsize (the main runtime image).
func findRuntimeImage(blob []byte, nold typ4Range) (uint64, error) {
	if nold.Offset > uint64(len(blob)) || nold.Size > uint64(len(blob))-nold.Offset {
		return 0, fmt.Errorf("nold range out of bounds: off=0x%x sz=0x%x len=0x%x",
			nold.Offset, nold.Size, len(blob))
	}
	end := nold.Offset + nold.Size

	var bestOff uint64
	var bestVMSize uint64
	found := false
	for _, moff := range findMachOMagics(blob, nold.Offset, end) {
		cmds, err := parseLoadCommands(blob, moff)
		if err != nil {
			continue
		}
		vmsize, ok := textVMSize(blob, cmds)
		if !ok {
			continue
		}
		if !found || vmsize > bestVMSize {
			bestOff = moff
			bestVMSize = vmsize
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("no runtime image with a __TEXT segment found in nold directory")
	}
	return bestOff, nil
}

// findMachOMagics returns every offset in [start, end) where an MH_MAGIC_64
// little-endian value appears.
func findMachOMagics(blob []byte, start, end uint64) []uint64 {
	var out []uint64
	for i := start; i+4 <= end; i++ {
		if binary.LittleEndian.Uint32(blob[i:i+4]) == mhMagic64 {
			out = append(out, i)
		}
	}
	return out
}

// parseLoadCommands walks the load commands of the Mach-O at base.
func parseLoadCommands(blob []byte, base uint64) ([]loadCmd, error) {
	if base+machoHdrSize > uint64(len(blob)) {
		return nil, fmt.Errorf("mach-o header at 0x%x out of bounds", base)
	}
	ncmds := binary.LittleEndian.Uint32(blob[base+hdrNcmdsOff:])
	off := base + machoHdrSize
	// ncmds is attacker-controlled here (a false-positive MH_MAGIC_64 found while
	// scanning the nold blob, or a malformed bundle), so never trust it for the
	// preallocation: cap by the bytes available (each load command is >= 8 bytes).
	// The loop below still validates each command against the blob length.
	capHint := uint64(ncmds)
	if maxCmds := (uint64(len(blob)) - off) / 8; capHint > maxCmds {
		capHint = maxCmds
	}
	cmds := make([]loadCmd, 0, capHint)
	for range ncmds {
		if off+lcHeaderSize > uint64(len(blob)) {
			return nil, fmt.Errorf("load command at 0x%x out of bounds", off)
		}
		cmd := binary.LittleEndian.Uint32(blob[off:])
		cmdSize := binary.LittleEndian.Uint32(blob[off+lcCmdSizeOff:])
		if cmdSize < lcHeaderSize {
			return nil, fmt.Errorf("undersized load command (cmdsize=0x%x) at 0x%x", cmdSize, off)
		}
		if off+uint64(cmdSize) > uint64(len(blob)) {
			return nil, fmt.Errorf("load command at 0x%x overruns blob: cmdsize=0x%x len=0x%x",
				off, cmdSize, len(blob))
		}
		cmds = append(cmds, loadCmd{cmd: cmd, off: off, cmdSize: cmdSize})
		off += uint64(cmdSize)
	}
	return cmds, nil
}

// textVMSize returns the vmsize of the __TEXT segment, if present.
func textVMSize(blob []byte, cmds []loadCmd) (uint64, bool) {
	for _, c := range cmds {
		if c.cmd != lcSegment64 || c.cmdSize < segment64Sz {
			continue
		}
		if segName(blob, c.off) != "__TEXT" {
			continue
		}
		return binary.LittleEndian.Uint64(blob[c.off+segVMSizeOff:]), true
	}
	return 0, false
}

// segName returns the 16-byte segname of an LC_SEGMENT_64 at coff.
func segName(blob []byte, coff uint64) string {
	raw := blob[coff+segNameOff : coff+segNameOff+segNameLen]
	n := 0
	for n < len(raw) && raw[n] != 0 {
		n++
	}
	return string(raw[:n])
}

// assembleRuntimeMachO builds the self-contained runtime Mach-O from the chosen
// header at moff, sourcing __TEXT from rtxt and the remaining segments from rdat.
func assembleRuntimeMachO(blob []byte, moff uint64, rtxt, rdat typ4Range) ([]byte, error) {
	cmds, err := parseLoadCommands(blob, moff)
	if err != nil {
		return nil, fmt.Errorf("failed to parse runtime image load commands: %v", err)
	}

	var hdrEnd uint64 = moff + machoHdrSize
	for _, c := range cmds {
		hdrEnd = c.off + uint64(c.cmdSize)
	}
	hdr := make([]byte, hdrEnd-moff)
	copy(hdr, blob[moff:hdrEnd])

	var segs []machoSegment
	for _, c := range cmds {
		rel := c.off - moff
		switch c.cmd {
		case lcSegment64:
			if c.cmdSize < segment64Sz {
				return nil, fmt.Errorf("undersized LC_SEGMENT_64 (cmdsize=0x%x) at 0x%x", c.cmdSize, c.off)
			}
			segs = append(segs, machoSegment{
				fileOff: binary.LittleEndian.Uint64(blob[c.off+segFileOff:]),
				fileSz:  binary.LittleEndian.Uint64(blob[c.off+segFileSzOff:]),
			})
		case lcSymtab:
			if c.cmdSize < symtabBodyEnd {
				return nil, fmt.Errorf("undersized LC_SYMTAB (cmdsize=0x%x) at 0x%x", c.cmdSize, c.off)
			}
			zero(hdr[rel+lcBodyOff : rel+symtabBodyEnd]) // symoff, nsyms, stroff, strsize
		case lcDysymtab:
			zero(hdr[rel+lcBodyOff : rel+uint64(c.cmdSize)])
		}
	}
	if len(segs) == 0 {
		return nil, fmt.Errorf("runtime image has no LC_SEGMENT_64 commands")
	}

	return layoutRuntimeMachO(blob, hdr, segs, rtxt.Offset, rdat.Offset)
}

// layoutRuntimeMachO writes the header and segment contents into the output
// buffer at their original file offsets.
func layoutRuntimeMachO(
	blob, hdr []byte, segs []machoSegment, rtxtOff, rdatOff uint64,
) ([]byte, error) {
	var outSz uint64
	for _, s := range segs {
		if s.fileSz == 0 {
			continue
		}
		if s.fileOff > maxOutputSize || s.fileSz > maxOutputSize-s.fileOff {
			return nil, fmt.Errorf("segment file range out of range: off=0x%x sz=0x%x", s.fileOff, s.fileSz)
		}
		if end := s.fileOff + s.fileSz; end > outSz {
			outSz = end
		}
	}
	if uint64(len(hdr)) > outSz { // the output must always hold the full header
		outSz = uint64(len(hdr))
	}
	out := make([]byte, outSz)

	// __TEXT (segs[0]) comes from the rtxt blob.
	textSz := segs[0].fileSz
	if err := copyRange(out, segs[0].fileOff, blob, rtxtOff, textSz, "rtxt"); err != nil {
		return nil, err
	}

	// Everything after __TEXT comes contiguously from the rdat blob.
	if len(segs) >= 2 {
		dataStart := segs[1].fileOff
		if dataStart > outSz {
			return nil, fmt.Errorf("runtime image data start 0x%x exceeds output size 0x%x",
				dataStart, outSz)
		}
		dataSpan := outSz - dataStart
		if err := copyRange(out, dataStart, blob, rdatOff, dataSpan, "rdat"); err != nil {
			return nil, err
		}
	}

	// Write the header/load commands last: a segment whose fileoff falls inside
	// the header range (e.g. __TEXT.fileoff == 0) must not clobber MH_MAGIC_64.
	copy(out, hdr)

	return out, nil
}

// copyRange copies n bytes from src[srcOff:] into dst[dstOff:], bounds-checking
// both sides. name labels the source range for error context.
func copyRange(dst []byte, dstOff uint64, src []byte, srcOff, n uint64, name string) error {
	if srcOff > uint64(len(src)) || n > uint64(len(src))-srcOff {
		return fmt.Errorf("%s range out of bounds: off=0x%x n=0x%x len=0x%x", name, srcOff, n, len(src))
	}
	if dstOff > uint64(len(dst)) || n > uint64(len(dst))-dstOff {
		return fmt.Errorf("output write out of bounds: off=0x%x n=0x%x len=0x%x", dstOff, n, len(dst))
	}
	copy(dst[dstOff:dstOff+n], src[srcOff:srcOff+n])
	return nil
}

// zero sets every byte in b to 0.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
