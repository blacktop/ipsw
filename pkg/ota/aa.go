package ota

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

type File struct {
	entry *yaa.Entry
	zf    *zip.File

	r  *Reader
	rr io.ReaderAt

	offset int64
}

// A Reader serves content from a Apple Archive.
type Reader struct {
	r    io.ReaderAt
	zr   *zip.Reader
	File []*zip.File
	yaa  *yaa.YAA

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
		r.File = append(r.File, zf)
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
			_ = bfiles
			// for _, bf := range bfiles {
			// if !bf.IsDir() {
			// 	r.Payload = append(r.Payload, &File{Entry: yaa.Entry{
			// 		Path: bf.Name(),
			// 		Type: yaa.RegularFile,
			// 		Size: uint32(bf.Size()),
			// 		Flag: uint32(bf.Mode()),
			// 		Mtm:  bf.ModTime(),
			// 		Mod:  bf.Mode(),
			// 	}, r: r, rr: rdr})
			// }
			// }
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
	}
	return nil
}

func (r *Reader) init(rdr io.ReaderAt, size int64) (err error) {
	r.r = rdr
	rs := io.NewSectionReader(rdr, 0, size)
	// buf := bufio.NewReader(rs)
	r.yaa, err = yaa.Parse(rs)
	if err != nil {
		return err
	}
	return nil
}

// var pbuf bytes.Buffer
// if err := pbzx.Extract(context.Background(), r, &pbuf, runtime.NumCPU()); err != nil {
// 	return nil, 0, err
// }
// pr := bytes.NewReader(pbuf.Bytes())

// OpenRaw returns a [Reader] that provides access to the [File]'s contents without
// decompression.
func (f *File) OpenRaw() io.Reader {
	// return io.NewSectionReader(f.rr, f.offset, int64(f.Size))
	return nil
}

// Open opens the named file in the ZIP archive,
// using the semantics of fs.FS.Open:
// paths are always slash separated, with no
// leading / or ../ elements.
// func (r *Reader) Open(name string) (fs.File, error) {
// 	// r.initFileList()

// 	if !fs.ValidPath(name) {
// 		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
// 	}
// 	e := r.openLookup(name)
// 	if e == nil {
// 		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
// 	}
// 	// if e.isDir {
// 	// 	return &openDir{e, r.openReadDir(name), 0}, nil
// 	// }
// 	rc := e.file.Open()
// 	// rc, err := e.file.Open()
// 	// if err != nil {
// 	// 	return nil, err
// 	// }
// 	return rc.(fs.File), nil
// }

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

// func sortFileByName(files []*File) {
// 	sort.Slice(files, func(i, j int) bool {
// 		return files[i].Path < files[j].Path
// 	})
// }

type fileListEntry struct {
	name  string
	file  *File
	isDir bool
}

type fileInfoDirEntry interface {
	fs.FileInfo
	fs.DirEntry
}
