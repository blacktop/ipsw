package bxdiff50

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/ulikunitz/xz"
)

const magic = "BXDIFF50"

type Header struct {
	Magic           [8]byte // "BXDIFF50"
	Version         uint64
	PatchedFileSize uint64
	ControlSize     uint64
	ExtraSize       uint64
	ResultSHA1      [20]byte
	DiffSize        uint64
	TargetSHA1      [20]byte
}

type Control struct {
	MixLen  int64
	CopyLen int64
	SeekLen int64
}

func readOffset(data []byte) int64 {
	var offset int64

	offset = int64(data[len(data)-1]) & 0x7f
	for i := len(data) - 2; i >= 0; i-- {
		offset = offset<<8 + int64(data[i])
	}
	if (data[len(data)-1] & 0x80) != 0 {
		offset = -offset
	}
	return offset
}

// xzMagic identifies an XZ stream (fd 37 7a 58 5a 00).
var xzMagic = []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}

// decompressStream handles both PBZX and raw XZ compressed data.
func decompressStream(data []byte) ([]byte, error) {
	if len(data) >= 6 && bytes.Equal(data[:6], xzMagic) {
		// Raw XZ stream
		r, err := xz.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("failed to create XZ reader: %w", err)
		}
		return io.ReadAll(r)
	}
	// Try PBZX
	var buf bytes.Buffer
	if err := pbzx.Extract(context.Background(), bytes.NewReader(data), &buf, runtime.NumCPU()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Patch(patch, target, output string) (err error) {
	f, err := os.Open(patch)
	if err != nil {
		return err
	}
	defer f.Close()

	var header Header
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return err
	}

	if string(header.Magic[:]) != magic {
		return errors.New("patch has invalid BXDIFF50 magic")
	}

	// Full-replacement mode: controlSize=0 means the data after the header
	// is PBZX-format chunks. Stream directly without loading into memory.
	if header.ControlSize == 0 {
		return extractFullReplacement(f, header, output, filepath.Base(target))
	}

	// For delta patches, load into memory (they need random access via bsdiff)
	f.Seek(int64(binary.Size(header)), io.SeekStart)
	dat, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	r := bytes.NewReader(dat)

	tf, err := os.Open(target)
	if err != nil {
		return err
	}
	defer tf.Close()

	// check input SHA1
	sha1Hash := sha1.New()
	if _, err := io.Copy(sha1Hash, tf); err != nil {
		return err
	}
	if !bytes.Equal(sha1Hash.Sum(nil), header.TargetSHA1[:]) {
		log.Errorf("input file SHA1 does not match expected SHA1 from patch: got %s, expected %s", hex.EncodeToString(sha1Hash.Sum(nil)), hex.EncodeToString(header.TargetSHA1[:]))
	}
	tf.Seek(0, io.SeekStart) // rewind

	// parse control data
	compControl := make([]byte, header.ControlSize)
	if _, err := r.Read(compControl); err != nil {
		return err
	}
	controlData, err := decompressStream(compControl)
	if err != nil {
		return fmt.Errorf("failed to decompress control data: %w", err)
	}
	cr := bytes.NewReader(controlData)

	// parse controls
	in := make([]byte, 8)
	var controls []Control
	for {
		var control Control
		if _, err := cr.Read(in); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		control.MixLen = readOffset(in)
		if _, err := cr.Read(in); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		control.CopyLen = readOffset(in)
		if _, err := cr.Read(in); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		control.SeekLen = readOffset(in)
		controls = append(controls, control)
	}

	// parse diff data
	compDiff := make([]byte, header.DiffSize)
	if _, err := r.Read(compDiff); err != nil {
		return err
	}
	diffData, err := decompressStream(compDiff)
	if err != nil {
		return fmt.Errorf("failed to decompress diff data: %w", err)
	}
	dr := bytes.NewReader(diffData)

	// parse extra data
	compExtra := make([]byte, header.ExtraSize)
	if _, err := r.Read(compExtra); err != nil {
		return err
	}

	extraData, err := decompressStream(compExtra)
	if err != nil {
		return fmt.Errorf("failed to decompress extra data: %w", err)
	}
	er := bytes.NewReader(extraData)

	var obuf bytes.Buffer

	// apply patch to output
	for _, control := range controls {
		if control.MixLen != 0 {
			indata := make([]uint8, control.MixLen)
			ddata := make([]uint8, control.MixLen)
			if err := binary.Read(tf, binary.LittleEndian, indata); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return err
			}
			if err := binary.Read(dr, binary.LittleEndian, ddata); err != nil {
				return err
			}
			for i := range indata {
				indata[i] += ddata[i]
			}
			if n, err := obuf.Write(indata); err != nil {
				return err
			} else if n != int(control.MixLen) {
				return errors.New("failed to write diff data")
			}
		}
		if control.CopyLen != 0 {
			exdata := make([]byte, control.CopyLen)
			if err := binary.Read(er, binary.LittleEndian, exdata); err != nil {
				return err
			}
			if n, err := obuf.Write(exdata); err != nil {
				return err
			} else if n != int(control.CopyLen) {
				return errors.New("failed to write extra data")
			}
		}
		if control.SeekLen != 0 {
			tf.Seek(control.SeekLen, io.SeekCurrent)
		}
	}

	// check output SHA1
	sha1Hash.Reset()
	if _, err := sha1Hash.Write(obuf.Bytes()); err != nil {
		return err
	}
	if !bytes.Equal(sha1Hash.Sum(nil), header.ResultSHA1[:]) {
		log.Errorf("output file SHA1 does not match expected SHA1 from patch: got %s, expected %s", hex.EncodeToString(sha1Hash.Sum(nil)), hex.EncodeToString(header.ResultSHA1[:]))
	}

	// write output
	if err := os.MkdirAll(output, 0o750); err != nil {
		return err
	}
	fname := filepath.Join(output, filepath.Base(target)+".patched")
	utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", fname))
	return os.WriteFile(fname, obuf.Bytes(), 0o660)
}

// extractFullReplacement handles BXDIFF50 patches with controlSize=0.
// The data is PBZX-format chunks (inflateSize/deflateSize BE pairs + XZ data)
// but the first chunk has no size pair — it starts with XZ directly.
// We find the first chunk boundary, synthesize a PBZX header, and delegate
// to the existing PBZX extractor.
func extractFullReplacement(r io.Reader, _ Header, output, baseName string) error {
	utils.Indent(log.Info, 2)("Decompressing full-replacement BXDIFF50 patch...")

	if err := os.MkdirAll(output, 0o750); err != nil {
		return err
	}

	fname := filepath.Join(output, baseName)
	outFile, err := os.Create(fname)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Read enough data to find the first XZ stream's end.
	// The first chunk is typically ~16KB compressed for 1MB decompressed.
	// Read 256KB to be safe, then find the YZ footer.
	probe := make([]byte, 256*1024)
	n, err := io.ReadFull(r, probe)
	if err != nil && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("failed to read patch data: %w", err)
	}
	probe = probe[:n]

	firstEnd := findXZStreamEnd(probe)
	if firstEnd <= 0 {
		// Single small XZ stream or can't find boundary — try direct XZ
		combined := io.MultiReader(bytes.NewReader(probe), r)
		xzr, err := xz.NewReader(combined)
		if err != nil {
			return fmt.Errorf("failed to read XZ stream: %w", err)
		}
		if _, err := io.Copy(outFile, xzr); err != nil {
			return fmt.Errorf("XZ decompression failed: %w", err)
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", fname))
		return nil
	}

	// Synthesize PBZX header + first chunk size pair, then stream the rest
	var hdr bytes.Buffer
	hdr.WriteString("pbzx")
	binary.Write(&hdr, binary.BigEndian, uint64(0x100000)) // blockSize = 1MB
	binary.Write(&hdr, binary.BigEndian, uint64(0x100000)) // first inflateSize
	binary.Write(&hdr, binary.BigEndian, uint64(firstEnd)) // first deflateSize

	// Assemble: [synth header][probe data][remaining stream data]
	pbzxStream := io.MultiReader(&hdr, bytes.NewReader(probe), r)

	if err := pbzx.Extract(context.Background(), pbzxStream, outFile, runtime.NumCPU()); err != nil {
		return fmt.Errorf("decompression failed: %w", err)
	}

	utils.Indent(log.Info, 2)(fmt.Sprintf("Created %s", fname))
	return nil
}

// findXZStreamEnd scans for the end of the first XZ stream.
// XZ footers end with 'YZ' (0x59, 0x5a). We verify by checking that
// the bytes following (aligned to 4) look like a PBZX chunk header.
func findXZStreamEnd(data []byte) int {
	for i := 10; i < len(data)-16; i++ {
		if data[i] == 0x59 && data[i+1] == 0x5a {
			end := (i + 2 + 3) &^ 3
			if end+16 > len(data) {
				continue
			}
			inflateSize := binary.BigEndian.Uint64(data[end : end+8])
			deflateSize := binary.BigEndian.Uint64(data[end+8 : end+16])
			if inflateSize > 0 && inflateSize <= 0x4000000 &&
				deflateSize > 0 && deflateSize <= inflateSize {
				return end
			}
		}
	}
	return -1
}
