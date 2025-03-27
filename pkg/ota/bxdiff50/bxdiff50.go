package bxdiff50

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
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

func Patch(patch, target, output string) (err error) {
	dat, err := os.ReadFile(patch)
	if err != nil {
		return err
	}

	r := bytes.NewReader(dat)

	var header Header
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return err
	}

	if string(header.Magic[:]) != magic {
		return errors.New("patch has invalid BXDIFF50 magic")
	}

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
	var cbuf bytes.Buffer
	if err := pbzx.Extract(context.Background(), bytes.NewReader(compControl), &cbuf, runtime.NumCPU()); err != nil {
		return err
	}
	cr := bytes.NewReader(cbuf.Bytes())

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
	var dbuf bytes.Buffer
	if err := pbzx.Extract(context.Background(), bytes.NewReader(compDiff), &dbuf, runtime.NumCPU()); err != nil {
		return err
	}
	dr := bytes.NewReader(dbuf.Bytes())

	// parse extra data
	compExtra := make([]byte, header.ExtraSize)
	if _, err := r.Read(compExtra); err != nil {
		return err
	}

	var ebuf bytes.Buffer
	if err := pbzx.Extract(context.Background(), bytes.NewReader(compExtra), &ebuf, runtime.NumCPU()); err != nil {
		return err
	}
	er := bytes.NewReader(ebuf.Bytes())

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
	log.Infof("Writing patched file to: %s", fname)
	return os.WriteFile(fname, obuf.Bytes(), 0o660)
}
