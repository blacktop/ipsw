package ota

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

const (
	MagicYAA1 = 0x31414159 // "YAA1"
	MagicAA01 = 0x31304141 // "AA01"
)

type File struct {
	yaa.Entry
	r  *Reader
	rr io.ReaderAt

	offset int64
}

// A Reader serves content from a Apple Archive.
type Reader struct {
	r       io.ReaderAt
	zr      *zip.Reader
	File    []*File
	Payload []*File

	// fileList is a list of files sorted by ename,
	// for use by the Open method.
	fileListOnce sync.Once
	fileList     []fileListEntry
}

type AA struct {
	f *os.File
	Reader
}

func getKeyFromName(name string) (string, error) {
	_, rest, ok := strings.Cut(name, "[")
	if !ok {
		return "", fmt.Errorf("begining of KEY '[' not found in '%s'", name)
	}
	key, _, ok := strings.Cut(rest, "]")
	if !ok {
		return "", fmt.Errorf("end of KEY ']' not found in '%s'", name)
	}
	key = strings.ReplaceAll(key, "-", "+")
	key = strings.ReplaceAll(key, "_", "/")
	return key, nil
}

func Open(name string) (*AA, error) {
	if isAEA, err := magic.IsAEA(name); err != nil {
		return nil, err
	} else if isAEA { // check if file is AEA encrypted
		key, _ := getKeyFromName(name)
		name, err = aea.Decrypt(&aea.DecryptConfig{
			Input:     name,
			Output:    os.TempDir(),
			B64SymKey: key,
		})
		if err != nil {
			return nil, err
		}
		defer os.Remove(name)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	r := new(AA)
	if isZip, err := magic.IsZip(name); err != nil {
		return nil, err
	} else if isZip { // check if file is a zip
		if err = r.initZip(f, fi.Size()); err != nil {
			f.Close()
			return nil, err
		}
	} else {
		if err = r.init(f, fi.Size()); err != nil {
			f.Close()
			return nil, err
		}
	}
	r.f = f
	return r, err
}

// Close closes the AA file, rendering it unusable for I/O.
func (a *AA) Close() error {
	return a.f.Close()
}

func (r *Reader) initZip(rdr io.ReaderAt, size int64) (err error) {
	r.zr, err = zip.NewReader(rdr, size)
	if err != nil {
		return err
	}
	for _, zf := range r.zr.File {
		f := &File{Entry: yaa.Entry{
			Path: zf.Name,
			Type: yaa.RegularFile,
			Size: uint32(zf.UncompressedSize64),
			Flag: uint32(zf.Flags),
			Mtm:  zf.Modified,
			Mod:  zf.Mode(),
		}, r: r, rr: rdr}
		if zf.FileInfo().IsDir() {
			f.Entry.Type = yaa.Directory
		}
		if strings.EqualFold(filepath.Base(zf.Name), "post.bom") {
			zr, err := zf.Open()
			if err != nil {
				return fmt.Errorf("failed to open post.bom: %v", err)
			}
			bdata := make([]byte, zf.UncompressedSize64)
			io.ReadFull(zr, bdata)
			zr.Close()
			bom, err := bom.New(bytes.NewReader(bdata))
			if err != nil {
				return fmt.Errorf("initZip: failed to parse BOM: %v", err)
			}
			bfiles, err := bom.GetPaths()
			if err != nil {
				return fmt.Errorf("initZip: failed to get BOM paths: %v", err)
			}
			for _, bf := range bfiles {
				if !bf.IsDir() {
					r.Payload = append(r.Payload, &File{Entry: yaa.Entry{
						Path: bf.Name(),
						Type: yaa.RegularFile,
						Size: uint32(bf.Size()),
						Flag: uint32(bf.Mode()),
						Mtm:  bf.ModTime(),
						Mod:  bf.Mode(),
					}, r: r, rr: rdr})
				}
			}
		}
		// if strings.Contains(f.Path, "payloadv2/payload.") && filepath.Ext(f.Path) != ".ecc" {
		// 	log.Debugf("Parsing payload %s", f.Path)
		// 	zff, err := zf.Open()
		// 	if err != nil {
		// 		return err
		// 	}
		// 	var pbuf bytes.Buffer
		// 	if err := pbzx.Extract(context.Background(), zff, &pbuf, runtime.NumCPU()); err != nil {
		// 		return err
		// 	}
		// 	pr := bytes.NewReader(pbuf.Bytes())
		// 	var magic uint32
		// 	var headerSize uint16
		// 	for {
		// 		var ent *Entry
		// 		err := binary.Read(pr, binary.LittleEndian, &magic)
		// 		if err != nil {
		// 			if err == io.EOF {
		// 				break
		// 			}
		// 			return err
		// 		}

		// 		if magic != MagicYAA1 && magic != MagicAA01 {
		// 			return fmt.Errorf("found unknown header magic: %x (%s)", magic, string(magic))
		// 		}
		// 		if err := binary.Read(pr, binary.LittleEndian, &headerSize); err != nil {
		// 			return err
		// 		}
		// 		if headerSize <= 5 {
		// 			return fmt.Errorf("invalid header size: %d", headerSize)
		// 		}

		// 		header := make([]byte, headerSize-uint16(binary.Size(magic))-uint16(binary.Size(headerSize)))
		// 		if err := binary.Read(pr, binary.LittleEndian, &header); err != nil {
		// 			return err
		// 		}
		// 		ent, err = yaaDecodeHeader(bytes.NewReader(header))
		// 		if err != nil {
		// 			// dump header if in Verbose mode
		// 			utils.Indent(log.Debug, 2)(hex.Dump(header))
		// 			return fmt.Errorf("failed to decode AA header: %v", err)
		// 		}
		// 		if ent.Type == RegularFile || ent.Type == Directory {
		// 			r.File = append(r.File, &File{Entry: *ent, aa: r, aar: pr})
		// 		}
		// 		pr.Seek(int64(ent.Size), io.SeekCurrent)
		// 	}
		// 	zff.Close()
		// }
		r.File = append(r.File, f)
	}
	return nil
}

func (r *Reader) init(rdr io.ReaderAt, size int64) error {
	r.r = rdr
	rs := io.NewSectionReader(rdr, 0, size)
	// buf := bufio.NewReader(rs)
	var magic uint32
	var headerSize uint16
	seen := make(map[string]bool)
	var total uint64
	var pfiles []*File
	for {
		var ent *yaa.Entry
		err := binary.Read(rs, binary.LittleEndian, &magic)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("init: failed to read magic: %v", err)
		}

		if magic != MagicYAA1 && magic != MagicAA01 {
			return fmt.Errorf("init: found unknown header magic: %x (%s)", magic, string(magic))
		}
		if err := binary.Read(rs, binary.LittleEndian, &headerSize); err != nil {
			return fmt.Errorf("init: failed to read header size: %v", err)
		}
		if headerSize <= 5 {
			return fmt.Errorf("init: invalid header size: %d", headerSize)
		}

		header := make([]byte, headerSize-uint16(binary.Size(magic))-uint16(binary.Size(headerSize)))
		if err := binary.Read(rs, binary.LittleEndian, &header); err != nil {
			return fmt.Errorf("init: failed to read header: %v", err)
		}
		ent, err = yaa.Decode(bytes.NewReader(header))
		if err != nil {
			// dump header if in Verbose mode
			utils.Indent(log.Debug, 2)(hex.Dump(header))
			return fmt.Errorf("init: failed to decode AA header: %v", err)
		}
		// if ent.Type == yaa.RegularFile || ent.Type == yaa.Directory {
		if ent.Type == yaa.RegularFile {
			curr, _ := rs.Seek(0, io.SeekCurrent)
			if ok := seen[ent.Path]; ok {
				continue
			}
			r.File = append(r.File, &File{Entry: *ent, r: r, rr: rdr, offset: curr})
			seen[ent.Path] = true
			if strings.EqualFold(filepath.Base(ent.Path), "post.bom") && ent.Size > 0 {
				bomData := make([]byte, ent.Size)
				if err := binary.Read(rs, binary.LittleEndian, &bomData); err != nil {
					return fmt.Errorf("init: failed to read BOM data: %v", err)
				}
				bom, err := bom.New(bytes.NewReader(bomData))
				if err != nil {
					return fmt.Errorf("init: failed to parse BOM: %v", err)
				}
				bpaths, err := bom.GetPaths()
				if err != nil {
					return fmt.Errorf("init: failed to get BOM paths: %v", err)
				}
				for _, bf := range bpaths {
					if !bf.IsDir() && bf.Size() > 0 {
						r.Payload = append(r.Payload, &File{Entry: yaa.Entry{
							Path: bf.Name(),
							Type: yaa.RegularFile,
							Size: uint32(bf.Size()),
							Flag: uint32(bf.Mode()),
							Mtm:  bf.ModTime(),
							Mod:  bf.Mode(),
						}, r: r, rr: rdr})
					}
				}
				// } else if strings.EqualFold(filepath.Base(ent.Path), "payload.000") && ent.Size > 0 {
			} else if strings.EqualFold(filepath.Base(ent.Path), "fixup.manifest") && ent.Size > 0 {
				pdata := make([]byte, ent.Size)
				if err := binary.Read(rs, binary.LittleEndian, &pdata); err != nil {
					return fmt.Errorf("init: failed to read payload data: %v", err)
				}
				var pbuf bytes.Buffer
				if err := pbzx.Extract(context.Background(), bytes.NewReader(pdata), &pbuf, runtime.NumCPU()); err != nil {
					return err
				}
				pfiles, total, err = parsePayloadV2(pbuf)
				if err != nil {
					return err
				}
				return nil
			} else {
				rs.Seek(int64(ent.Size), io.SeekCurrent)
			}
		}
	}
	_ = pfiles
	btotal := uint64(0)
	for idx, bf := range r.Payload {
		if bf.Path != pfiles[idx].Path {
			log.Errorf("Payload file mismatch: '%s' != '%s'", bf.Path, pfiles[idx].Path)
		}
		btotal += uint64(bf.Size)
		if btotal > total {
			fmt.Printf("Found all payload files: %d\n", idx)
			break
		}
	}
	return nil
}

// Open returns a [SectionReader] that provides access to the [File]'s contents.
// Multiple files may be read concurrently.
func (f *File) Open() *io.SectionReader {
	return io.NewSectionReader(f.rr, f.offset, int64(f.Size))
}

// Open opens the named file in the ZIP archive,
// using the semantics of fs.FS.Open:
// paths are always slash separated, with no
// leading / or ../ elements.
func (r *Reader) Open(name string) (fs.File, error) {
	// r.initFileList()

	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	e := r.openLookup(name)
	if e == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	// if e.isDir {
	// 	return &openDir{e, r.openReadDir(name), 0}, nil
	// }
	rc := e.file.Open()
	// rc, err := e.file.Open()
	// if err != nil {
	// 	return nil, err
	// }
	return rc.(fs.File), nil
}

func split(name string) (dir, elem string, isDir bool) {
	if len(name) > 0 && name[len(name)-1] == '/' {
		isDir = true
		name = name[:len(name)-1]
	}
	i := len(name) - 1
	for i >= 0 && name[i] != '/' {
		i--
	}
	if i < 0 {
		return ".", name, isDir
	}
	return name[:i], name[i+1:], isDir
}

var dotFile = &fileListEntry{name: "./", isDir: true}

func (r *Reader) openLookup(name string) *fileListEntry {
	if name == "." {
		return dotFile
	}

	dir, elem, _ := split(name)
	files := r.fileList
	i := sort.Search(len(files), func(i int) bool {
		idir, ielem, _ := split(files[i].name)
		return idir > dir || idir == dir && ielem >= elem
	})
	if i < len(files) {
		fname := files[i].name
		if fname == name || len(fname) == len(name)+1 && fname[len(name)] == '/' && fname[:len(name)] == name {
			return &files[i]
		}
	}
	return nil
}

func parsePayloadV2(pbuf bytes.Buffer) ([]*File, uint64, error) {
	var total uint64

	var magic uint32
	var headerSize uint16

	pr := bytes.NewReader(pbuf.Bytes())

	var fs []*File

	for {
		var ent *yaa.Entry
		err := binary.Read(pr, binary.LittleEndian, &magic)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, 0, err
		}

		if magic != MagicYAA1 && magic != MagicAA01 {
			return nil, 0, fmt.Errorf("found unknown header magic: %x (%s)", magic, string(magic))
		}
		if err := binary.Read(pr, binary.LittleEndian, &headerSize); err != nil {
			return nil, 0, err
		}
		if headerSize <= 5 {
			return nil, 0, fmt.Errorf("invalid header size: %d", headerSize)
		}

		header := make([]byte, headerSize-uint16(binary.Size(magic))-uint16(binary.Size(headerSize)))
		if err := binary.Read(pr, binary.LittleEndian, &header); err != nil {
			return nil, 0, err
		}
		ent, err = yaa.Decode(bytes.NewReader(header))
		if err != nil {
			// dump header if in Verbose mode
			utils.Indent(log.Debug, 2)(hex.Dump(header))
			return nil, 0, fmt.Errorf("failed to decode AA header: %v", err)
		}
		// if ent.Type == yaa.RegularFile || ent.Type == yaa.Directory {
		if ent.Type == yaa.RegularFile {
			log.Debug(ent.String())
			total += uint64(ent.Size)
			fs = append(fs, &File{Entry: *ent})
		}
		pr.Seek(int64(ent.Size), io.SeekCurrent)
	}

	sortFileByName(fs)

	return fs, total, nil
}

func sortFileByName(files []*File) {
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
}

type fileListEntry struct {
	name  string
	file  *File
	isDir bool
}

type fileInfoDirEntry interface {
	fs.FileInfo
	fs.DirEntry
}
