package fw

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/bundle"
)

func Extract(input, output string) ([]string, error) {
	var m *macho.File
	var outfiles []string

	bn, err := bundle.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %v", err)
	}

	if bn.Type != 3 {
		return nil, fmt.Errorf("bundle is not an exclave bundle")
	}

	f, err := os.Open(input)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", input, err)
	}
	defer f.Close()

	assetIndex := 0

	for idx, bf := range bn.Files {
		fname := filepath.Join(output, bf.Type, bf.Name)
		if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %v", filepath.Dir(fname), err)
		}

		of, err := os.Create(fname)
		if err != nil {
			return nil, fmt.Errorf("failed to create file %s: %v", fname, err)
		}
		defer of.Close()

		if len(bf.Segments) == 0 { // FIXME: should this be removed?
			continue
		}

		entry := bn.Config.TOC[idx].GetEntry()

		switch {
		case entry == nil: // APP (MachO)
			text := bf.Segment("TEXT")
			if text == nil {
				text = bf.Segment("HEADER")
				if text == nil {
					return nil, fmt.Errorf("failed to find TEXT segment")
				}
			}
			if _, err := f.Seek(int64(text.Offset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to offset %d: %v", text.Offset, err)
			}
			tdata := make([]byte, text.Size)
			if err := binary.Read(f, binary.LittleEndian, &tdata); err != nil {
				return nil, fmt.Errorf("failed to read data from file %s: %v", fname, err)
			}
			m, err = macho.NewFile(bytes.NewReader(tdata), macho.FileConfig{
				LoadIncluding: []types.LoadCmd{types.LC_SEGMENT_64},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to parse MachO file: %v", err)
			}
			defer m.Close()
		case bf.Type == "SYSTEM": // ASSET (SYSTEM kernel)
			if _, err := f.Seek(int64(bn.Config.Assets[assetIndex].Offset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to offset %d: %v", bn.Config.Assets[assetIndex].Offset, err)
			}
			mHdrData := make([]byte, bn.Config.Assets[assetIndex].Size) // __MACHOHEADERLC
			if err := binary.Read(f, binary.LittleEndian, &mHdrData); err != nil {
				return nil, fmt.Errorf("failed to read data from file %s: %v", fname, err)
			}
			m, err = macho.NewFile(bytes.NewReader(mHdrData), macho.FileConfig{
				LoadIncluding: []types.LoadCmd{types.LC_SEGMENT_64},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to parse MachO file: %v", err)
			}
			defer m.Close()
			// write MACHOHEADERLC to output file
			if _, err := of.Write(mHdrData); err != nil {
				return nil, fmt.Errorf("failed to write data to file %s: %v", fname, err)
			}
			assetIndex++
		default: // ASSET (APP non-MachO)
			fname := filepath.Join(output, bf.Type, string(entry.Name.Bytes))
			attr, err := os.Create(fname)
			if err != nil {
				return nil, fmt.Errorf("failed to create file %s: %v", fname, err)
			}
			defer attr.Close()
			if _, err := f.Seek(int64(bn.Config.Assets[assetIndex].Offset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to offset %d: %v", bn.Config.Assets[assetIndex].Offset, err)
			}
			adata := make([]byte, bn.Config.Assets[assetIndex].Size) // brkr_artifact
			if err := binary.Read(f, binary.LittleEndian, &adata); err != nil {
				return nil, fmt.Errorf("failed to read data from file %s: %v", fname, err)
			}
			// TODO: parse 'brkr_artifact' which is a map[string]any or a plist essentially
			// var brkr map[string]any
			// if _, err := asn1.Unmarshal(adata, &brkr); err != nil {
			// 	return nil, fmt.Errorf("failed to unmarshal data from file %s: %v", fname, err)
			// }
			// os.WriteFile(filepath.Join(output, bf.Type, "data.json"), adata, 0o644)
			if _, err := attr.Write(adata); err != nil {
				return nil, fmt.Errorf("failed to write data to file %s: %v", fname, err)
			}
			outfiles = append(outfiles, fname)
			assetIndex++
			continue
		}

		for _, sec := range bf.Sections {
			if _, err := f.Seek(int64(sec.Offset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to offset %d: %v", sec.Offset, err)
			}
			data := make([]byte, sec.Size)
			if err := binary.Read(f, binary.LittleEndian, &data); err != nil {
				return nil, fmt.Errorf("failed to read data from file %s: %v", fname, err)
			}
			if s := m.Segment("__" + sec.Name); s == nil { // lookup segment in MachO header
				return nil, fmt.Errorf("failed to find segment %s", sec.Name)
			} else {
				if _, err := of.WriteAt(data, int64(s.Offset)); err != nil {
					return nil, fmt.Errorf("failed to write data to file %s: %v", fname, err)
				}
			}
		}
		outfiles = append(outfiles, fname)
	}

	return outfiles, nil
}
