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

// ShowExclaveCores prints information about the Exclave cores in the bundle.
func ShowExclaveCores(data []byte) {
	bn, err := bundle.Parse(bytes.NewReader(data))
	if err != nil {
		fmt.Printf("failed to open bundle: %v\n", err)
		return
	}
	if bn.Type != 3 {
		fmt.Printf("bundle is not an exclave bundle\n")
		return
	}
	fmt.Println(bn)
}

func ExtractExclaveCores(data []byte, output string) ([]string, error) {
	var m *macho.File
	var outfiles []string

	// os.WriteFile(filepath.Join(output, "exclave.bundle"), data, 0o644)

	bn, err := bundle.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to open exclave bundle: %v", err)
	}
	defer bn.Close()

	if bn.Type != 3 {
		return nil, fmt.Errorf("bundle is not an exclave bundle")
	}

	r := bytes.NewReader(data)

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

		if idx == 0 { // SYSTEM/kernel
			if _, err := r.Seek(int64(bn.Config.Assets[idx].Offset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to offset %d: %v", bn.Config.Assets[idx].Offset, err)
			}
			mHdrData := make([]byte, bn.Config.Assets[idx].Size)
			if err := binary.Read(r, binary.LittleEndian, &mHdrData); err != nil {
				return nil, fmt.Errorf("failed to read data from file %s: %v", fname, err)
			}
			m, err = macho.NewFile(bytes.NewReader(mHdrData), macho.FileConfig{
				LoadIncluding: []types.LoadCmd{types.LC_SEGMENT_64},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to parse MachO file: %v", err)
			}
			// write MACHOHEADERLC to kernel
			if _, err := of.Write(mHdrData); err != nil {
				return nil, fmt.Errorf("failed to write data to file %s: %v", fname, err)
			}
		} else {
			text := bf.Segment("TEXT")
			if text == nil {
				text = bf.Segment("HEADER")
				if text == nil {
					return nil, fmt.Errorf("failed to find TEXT segment")
				}
			}
			if _, err := r.Seek(int64(text.Offset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to offset %d: %v", text.Offset, err)
			}
			tdata := make([]byte, text.Size)
			if err := binary.Read(r, binary.LittleEndian, &tdata); err != nil {
				return nil, fmt.Errorf("failed to read data from file %s: %v", fname, err)
			}
			m, err = macho.NewFile(bytes.NewReader(tdata), macho.FileConfig{
				LoadIncluding: []types.LoadCmd{types.LC_SEGMENT_64},
			})
			if err != nil {
				return nil, fmt.Errorf("failed to parse MachO file: %v", err)
			}
		}
		// write data to correct offsets
		for _, sec := range bf.Sections {
			if _, err := r.Seek(int64(sec.Offset), io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek to offset %d in file %s: %v", sec.Offset, fname, err)
			}
			data := make([]byte, sec.Size)
			if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
				return nil, fmt.Errorf("failed to read data from file %s: %v", fname, err)
			}
			if s := m.Segment("__" + sec.Name); s == nil { // lookup segment in MachO header
				return nil, fmt.Errorf("failed to find segment %s for %s", sec.Name, fname)
			} else {
				if _, err := of.WriteAt(data, int64(s.Offset)); err != nil {
					return nil, fmt.Errorf("failed to write data to file %s: %v", fname, err)
				}
			}
		}
		m.Close()

		outfiles = append(outfiles, fname)

		/* ASSET file */
		if entry := bn.Config.TOC[idx].GetEntry(); entry != nil && idx > 0 {
			for _, asset := range bn.Config.Assets {
				if entry.Type == asset.Type {
					aname := fname + "." + string(entry.Name.Bytes)
					attr, err := os.Create(aname)
					if err != nil {
						return nil, fmt.Errorf("failed to create file %s: %v", aname, err)
					}
					defer attr.Close()
					if _, err := r.Seek(int64(asset.Offset), io.SeekStart); err != nil {
						return nil, fmt.Errorf("failed to seek to offset %d: %v", asset.Offset, err)
					}
					adata := make([]byte, asset.Size) // brkr_artifact
					if err := binary.Read(r, binary.LittleEndian, &adata); err != nil {
						return nil, fmt.Errorf("failed to read data from file %s: %v", aname, err)
					}
					// TODO: parse 'brkr_artifact' which is a map[string]any or a plist essentially
					// var brkr map[string]any
					// if _, err := asn1.Unmarshal(adata, &brkr); err != nil {
					// 	return nil, fmt.Errorf("failed to unmarshal data from file %s: %v", aname, err)
					// }
					// os.WriteFile(filepath.Join(output, bf.Type, "data.json"), adata, 0o644)
					if _, err := attr.Write(adata); err != nil {
						return nil, fmt.Errorf("failed to write data to file %s: %v", aname, err)
					}
					outfiles = append(outfiles, aname)
				}
			}
		}
	}

	return outfiles, nil
}
