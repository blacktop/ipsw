package ota

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
)

type File struct {
	name  string
	isDir bool
	isDup bool

	entry *yaa.Entry
	zfile *zip.File
}

// A Reader serves content from a Apple Archive.
type Reader struct {
	r  io.ReaderAt
	zr *zip.Reader

	zfiles []*zip.File
	yaa    *yaa.YAA

	isZip bool

	// fileList is a list of files sorted by ename,
	// for use by the Open method.
	fileListOnce sync.Once
	fileList     []*File
	bomFiles     []fs.FileInfo
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
	if r.isZip, err = magic.IsZip(name); err != nil {
		return nil, err
	} else if r.isZip { // check if file is a zip
		r.isZip = true
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
	r.zfiles = r.zr.File
	return nil
}

func (r *Reader) init(rdr io.ReaderAt, size int64) (err error) {
	r.r = rdr
	rs := io.NewSectionReader(rdr, 0, size)
	r.yaa, err = yaa.Parse(rs)
	if err != nil {
		return err
	}
	return nil
}

// toValidName coerces name to be a valid name for fs.FS.Open.
func toValidName(name string) string {
	name = strings.ReplaceAll(name, `\`, `/`)
	p := path.Clean(name)
	p = strings.TrimPrefix(p, "/")
	for strings.HasPrefix(p, "../") {
		p = p[len("../"):]
	}
	return p
}

func (r *Reader) initFileList() {
	r.fileListOnce.Do(func() {
		// files and knownDirs map from a file/directory name
		// to an index into the r.fileList entry that we are
		// building. They are used to mark duplicate entries.
		files := make(map[string]int)
		knownDirs := make(map[string]int)

		// dirs[name] is true if name is known to be a directory,
		// because it appears as a prefix in a path.
		dirs := make(map[string]bool)

		for _, file := range r.zfiles {
			isDir := len(file.Name) > 0 && file.Name[len(file.Name)-1] == '/'
			name := toValidName(file.Name)
			if name == "" {
				continue
			}

			if idx, ok := files[name]; ok {
				r.fileList[idx].isDup = true
				continue
			}
			if idx, ok := knownDirs[name]; ok {
				r.fileList[idx].isDup = true
				continue
			}

			for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
				dirs[dir] = true
			}

			idx := len(r.fileList)
			entry := &File{
				name:  name,
				zfile: file,
				isDir: isDir,
			}
			r.fileList = append(r.fileList, entry)
			if isDir {
				knownDirs[name] = idx
			} else {
				files[name] = idx
			}
			if strings.EqualFold(filepath.Base(file.Name), "post.bom") {
				if zr, err := file.Open(); err == nil {
					bdata := make([]byte, file.UncompressedSize64)
					if _, err := zr.Read(bdata); err == nil {
						if bom, err := bom.New(bytes.NewReader(bdata)); err == nil {
							if bfiles, err := bom.GetPaths(); err == nil {
								r.bomFiles = bfiles
							}
						}
					}
				}
			}
		}
		for dir := range dirs {
			if _, ok := knownDirs[dir]; !ok {
				if idx, ok := files[dir]; ok {
					r.fileList[idx].isDup = true
				} else {
					entry := &File{
						name:  dir,
						zfile: nil,
						isDir: true,
					}
					r.fileList = append(r.fileList, entry)
				}
			}
		}
		if r.yaa != nil {
			for _, entry := range r.yaa.Entries {
				if entry.Type != yaa.RegularFile && entry.Type != yaa.Directory {
					continue
				}
				name := toValidName(entry.Path)
				if name == "" {
					continue
				}
				if idx, ok := files[name]; ok {
					r.fileList[idx].isDup = true
					continue
				}
				if idx, ok := knownDirs[name]; ok {
					r.fileList[idx].isDup = true
					continue
				}
				for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
					dirs[dir] = true
				}
				idx := len(r.fileList)
				entry := &File{
					name:  name,
					entry: entry,
					isDir: entry.IsDir(),
				}
				r.fileList = append(r.fileList, entry)
				if entry.IsDir() {
					knownDirs[name] = idx
				} else {
					files[name] = idx
				}
			}
			// add BOM files
			// TODO: some of these aren't in the payloads ??
			if bomFiles, err := r.yaa.PostBOM(); err == nil {
				r.bomFiles = bomFiles
			}
		}

		sort.Slice(r.fileList, func(i, j int) bool { return fileEntryLess(r.fileList[i].name, r.fileList[j].name) })
	})
}

func fileEntryLess(x, y string) bool {
	xdir, xelem, _ := split(x)
	ydir, yelem, _ := split(y)
	return xdir < ydir || xdir == ydir && xelem < yelem
}

func (r *Reader) Files() []*File {
	r.initFileList()
	return r.fileList
}

func (r *Reader) PostFiles() []fs.FileInfo {
	r.initFileList()
	return r.bomFiles
}

// Open opens the named file in the ZIP archive,
// using the semantics of fs.FS.Open:
// paths are always slash separated, with no
// leading / or ../ elements.
func (r *Reader) Open(name string) (fs.File, error) {
	r.initFileList()

	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	e := r.openLookup(name)
	if e == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	rc, err := e.Open()
	if err != nil {
		return nil, err
	}
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

var dotFile = &File{name: "./", isDir: true}

func (r *Reader) openLookup(name string) *File {
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
			return files[i]
		}
	}
	return nil
}

func (f *File) Name() string { _, elem, _ := split(f.name); return elem }
func (f *File) Path() string { return f.name }
func (f *File) Size() int64 {
	if f.zfile != nil {
		return int64(f.zfile.UncompressedSize64)
	} else {
		return int64(f.entry.Size)
	}
}
func (f *File) Mode() fs.FileMode {
	if f.zfile != nil {
		return f.zfile.Mode()
	} else {
		return f.entry.Mod
	}
}
func (f *File) ModTime() time.Time {
	if f.zfile != nil {
		return f.zfile.Modified
	} else {
		return f.entry.Mtm
	}
}
func (f *File) Type() fs.FileMode          { return fs.ModeDir }
func (f *File) IsDir() bool                { return f.isDir }
func (f *File) Sys() any                   { return nil }
func (f *File) Stat() (fs.FileInfo, error) { return f, nil }

type otaReader struct {
	rc io.ReadCloser
	f  *File
}

func (r *otaReader) Stat() (fs.FileInfo, error) {
	return r.f, nil
}

func (r *otaReader) Read(b []byte) (n int, err error) {
	return r.rc.Read(b)
}

func (r *otaReader) Close() error { return r.rc.Close() }

func (f *File) Open() (io.ReadCloser, error) {
	var mdata [4]byte
	var rc io.ReadCloser
	if f.zfile != nil {
		zf, err := f.zfile.Open()
		if err != nil {
			return nil, err
		}
		if _, err := zf.Read(mdata[:]); err != nil {
			return nil, err
		}
		zf.Close()
		switch magic.Magic(binary.BigEndian.Uint32(mdata[:])) {
		case magic.MagicPBZX:
			var pbuf bytes.Buffer
			zf, err := f.zfile.Open()
			if err != nil {
				return nil, err
			}
			if err := pbzx.Extract(context.Background(), zf, &pbuf, runtime.NumCPU()); err != nil {
				return nil, err
			}
			rc = &otaReader{
				rc: io.NopCloser(bytes.NewReader(pbuf.Bytes())),
				f:  f,
			}
			zf.Close()
			return rc, nil
		case magic.MagicYAA1, magic.MagicAA01:
			zf.Close()
			return f.zfile.Open()
		default:
			zf.Close()
			return nil, fmt.Errorf("unknown magic: %v", mdata)
		}
	}
	if _, err := f.entry.Read(mdata[:]); err != nil {
		return nil, err
	}
	switch magic.Magic(binary.BigEndian.Uint32(mdata[:])) {
	case magic.MagicPBZX:
		data := make([]byte, f.entry.Size)
		if _, err := f.entry.Read(data); err != nil {
			return nil, err
		}
		var pbuf bytes.Buffer
		if err := pbzx.Extract(context.Background(), bytes.NewReader(data), &pbuf, runtime.NumCPU()); err != nil {
			return nil, err
		}
		rc = &otaReader{
			rc: io.NopCloser(bytes.NewReader(pbuf.Bytes())),
			f:  f,
		}
		return rc, nil
	case magic.MagicYAA1, magic.MagicAA01:
		edata := make([]byte, f.entry.Size)
		if _, err := f.entry.Read(edata); err != nil {
			return nil, err
		}
		rc = &otaReader{
			rc: io.NopCloser(bytes.NewReader(edata)),
			f:  f,
		}
		return rc, nil
	default:
		return nil, fmt.Errorf("unknown magic: %v", mdata)
	}
}
