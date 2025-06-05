package ota

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/blacktop/ipsw/pkg/ota/ridiff"
	"github.com/blacktop/ipsw/pkg/ota/yaa"
	"github.com/dustin/go-humanize"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/execabs"
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

	payloadMapOnce sync.Once
	payloadMap     map[string]string
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

func NewOTA(r io.ReaderAt, size int64) (*AA, error) {
	var err error
	f := new(AA)
	if f.isZip, err = magic.IsZipData(io.NewSectionReader(r, 0, 4)); err != nil {
		return nil, err
	} else if f.isZip { // check if file is a zip
		f.isZip = true
		if err := f.initZip(r, size); err != nil {
			return nil, err
		}
	} else {
		if err := f.init(r, size); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func Open(name string, symmetricKey ...string) (*AA, error) {
	if isAEA, err := magic.IsAEA(name); err != nil {
		return nil, err
	} else if isAEA { // check if file is AEA encrypted
		var key string
		if len(symmetricKey) > 0 && symmetricKey[0] != "" {
			key = symmetricKey[0]
		} else {
			key, err = getKeyFromName(name)
			if err != nil {
				return nil, fmt.Errorf("failed to get key from name: %v (must supply --key-val)", err)
			}
		}
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

func (a *AA) Info() (*info.Info, error) {
	var pfiles []fs.File
	for _, file := range a.Files() {
		switch {
		case regexp.MustCompile(`.*DeviceTree.*im4p$`).MatchString(file.Path()):
			fallthrough
		case regexp.MustCompile(`^Info.plist$`).MatchString(file.Path()):
			fallthrough
		case regexp.MustCompile(`^AssetData/Info.plist$`).MatchString(file.Path()):
			fallthrough
		case regexp.MustCompile(`Restore.plist$`).MatchString(file.Path()):
			fallthrough
		case regexp.MustCompile(`BuildManifest.plist$`).MatchString(file.Path()):
			fallthrough
		case regexp.MustCompile(`SystemVersion.plist$`).MatchString(file.Path()):
			f, err := a.Open(file.Path(), true)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			pfiles = append(pfiles, f)
		}
	}
	if len(pfiles) == 0 {
		return nil, fmt.Errorf("no plist files found")
	}
	return info.ParseOTAFiles(pfiles)
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
	r.yaa = &yaa.YAA{}
	rs := io.NewSectionReader(rdr, 0, size)
	if err := r.yaa.Parse(rs); err != nil {
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

func (r *Reader) initFileList() (ferr error) {
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
				zr, err := file.Open()
				if err != nil {
					ferr = err
					return
				}
				bdata, err := io.ReadAll(zr)
				if err != nil {
					ferr = err
					return
				}
				bom, err := bom.New(bytes.NewReader(bdata))
				if err != nil {
					ferr = err
					return
				}
				bfiles, err := bom.GetPaths()
				if err != nil {
					ferr = err
					return
				}
				r.bomFiles = bfiles
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
			bomFiles, err := r.yaa.PostBOM()
			if err != nil {
				if !errors.Is(err, yaa.ErrPostBomNotFound) {
					ferr = err
					return
				}
			} else {
				r.bomFiles = bomFiles
			}
		}

		sort.Slice(r.fileList, func(i, j int) bool { return fileEntryLess(r.fileList[i].name, r.fileList[j].name) })
	})

	return ferr
}

func (r *Reader) initPayloadMap() (perr error) {
	r.payloadMapOnce.Do(func() {
		pre := regexp.MustCompile(`^payload.\d+$`)
		r.payloadMap = make(map[string]string)
		hdr := make([]byte, binary.Size(pbzx.Header{}))
		var pbuf bytes.Buffer
		for _, file := range r.Files() {
			if file.isDir {
				continue
			}
			if pre.MatchString(file.Name()) {
				f, err := r.Open(file.Path(), false)
				if err != nil {
					perr = err
					return
				}
				defer f.Close()
				var header pbzx.Header
				if err := binary.Read(f, binary.BigEndian, &header); err != nil {
					perr = fmt.Errorf("failed to read pbzx header: %v", err)
					return
				}
				if err := binary.Write(bytes.NewBuffer(hdr[:0]), binary.BigEndian, &header); err != nil {
					perr = fmt.Errorf("failed to write pbzx header: %v", err)
					return
				}
				cache := make([]byte, header.DeflateSize)
				if _, err := f.Read(cache); err != nil {
					perr = fmt.Errorf("failed to read pbzx block: %v", err)
					return
				}
				block := make([]byte, len(hdr)+int(header.DeflateSize))
				copy(block, hdr)
				copy(block[len(hdr):], cache)
				if err := pbzx.Extract(context.Background(), bytes.NewReader(block), &pbuf, runtime.NumCPU()); err != nil {
					perr = err
					return
				}
				aa := &yaa.YAA{}
				if err := aa.Parse(bytes.NewReader(pbuf.Bytes())); err != nil {
					if !errors.Is(err, io.ErrUnexpectedEOF) {
						perr = fmt.Errorf("failed to parse payload: %v", err)
						return
					}
				}
				for _, entry := range aa.Entries {
					if entry.Type == yaa.RegularFile && entry.Path != "" && entry.Size > 0 {
						r.payloadMap[file.Name()] = entry.Path
						pbuf.Reset()
						break
					}
				}
			}
		}
	})

	return
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

func (r *Reader) GetPayloadFiles(pattern, payloadRange, output string) error {
	r.initFileList()
	pre := regexp.MustCompile(`^payload.\d+$`)
	if payloadRange != "" {
		pre = regexp.MustCompile(payloadRange)
	}
	eg, _ := errgroup.WithContext(context.Background())
	for _, file := range r.Files() {
		if file.isDir {
			continue
		}
		if pre.MatchString(file.Name()) {
			eg.Go(func() error {
				f, err := r.Open(file.Path(), false)
				if err != nil {
					return err
				}
				defer f.Close()
				tmpdir, err := os.MkdirTemp("", "ota_payload_extract")
				if err != nil {
					return err
				}
				defer os.RemoveAll(tmpdir)
				if err := aaExtractPattern(f, pattern, tmpdir); err != nil {
					return err
				}
				if err := filepath.Walk(tmpdir, func(path string, f os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if !f.IsDir() {
						fname := filepath.Join(output, filepath.Clean(strings.TrimPrefix(path, tmpdir)))
						if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
							return fmt.Errorf("failed to create dir %s: %v", filepath.Dir(fname), err)
						}
						utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting from '%s' -> %s\t%s", file.Name(), humanize.Bytes(uint64(f.Size())), fname))
						if err := os.Rename(path, fname); err != nil {
							return fmt.Errorf("failed to mv file %s to %s: %v", strings.TrimPrefix(path, tmpdir), fname, err)
						}
					}
					return nil
				}); err != nil {
					return fmt.Errorf("failed to read files in tmp folder: %v", err)
				}
				return nil
			})
		}
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

func (r *Reader) PayloadFiles(pattern string, json bool) error {
	r.initFileList()
	pre := regexp.MustCompile(`^payload.\d+$`)
	// TODO: add mutex around writing to stdout
	eg, _ := errgroup.WithContext(context.Background())
	for _, file := range r.Files() {
		if file.isDir {
			continue
		}
		if pre.MatchString(file.Name()) {
			eg.Go(func() error {
				f, err := r.Open(file.Path(), false)
				if err != nil {
					return err
				}
				defer f.Close()
				out, err := aaList(f, pattern, json)
				if err != nil {
					return err
				}
				if len(out) > 0 && out != "[]" {
					fmt.Println(out)
				}
				return nil
			})
		}
	}
	if err := eg.Wait(); err != nil {
		return err
	}
	return nil
}

func aaList(in io.Reader, pattern string, json bool) (string, error) {
	aaPath, err := execabs.LookPath("aa")
	if err != nil {
		return "", err
	}

	args := []string{"list", "-exclude-field", "all", "-include-field", "attr"}

	if len(pattern) > 0 {
		args = append(args, []string{"-include-regex", pattern}...)
	}
	if json {
		args = append(args, []string{"-list-format", "json"}...)
	}
	if len(pattern) == 0 && !json {
		args = append(args, "-v")
	}

	cmd := exec.Command(aaPath, args...)
	cmd.Stdin = in
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, out)
	}

	return strings.TrimSpace(string(out)), nil
}

func aaExtractPattern(in io.Reader, pattern, output string) error {
	aaPath, err := execabs.LookPath("aa")
	if err != nil {
		return err
	}
	cmd := exec.Command(aaPath, "extract", "-d", output, "-include-regex", pattern)
	cmd.Stdin = in
	out, err := cmd.CombinedOutput()
	if err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			return fmt.Errorf("%v: %s", err, out)
		}
	}
	return nil
}

func (r *Reader) ExtractCryptex(cryptex, output string) (string, error) {
	var re *regexp.Regexp
	switch cryptex {
	case "system":
		re = regexp.MustCompile(`cryptex-system-(arm64e?|x86_64h?)$`)
	case "app":
		re = regexp.MustCompile(`cryptex-app$`)
	default:
		return "", fmt.Errorf("unknown cryptex type '%s'", cryptex)
	}

	tmpdir, err := os.MkdirTemp("", "ota_extract_cryptexes")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	for _, file := range r.Files() {
		if re.MatchString(file.Name()) {
			cryptexFile, err := r.Open(file.Path(), false)
			if err != nil {
				return "", fmt.Errorf("failed to open cryptex file: %v", err)
			}
			defer cryptexFile.Close()
			// create a temp file to hold the OTA cryptex
			cf, err := os.Create(filepath.Join(tmpdir, file.Name()))
			if err != nil {
				return "", fmt.Errorf("failed to create file: %v", err)
			}
			// create a temp file to hold the PATCHED OTA cryptex DMG
			dcf, err := os.Create(filepath.Join(output, file.Name()+".dmg"))
			if err != nil {
				return "", fmt.Errorf("failed to create file: %v", err)
			}
			dcf.Close()
			if _, err := io.Copy(cf, cryptexFile); err != nil {
				return "", fmt.Errorf("failed to write file: %v", err)
			}
			cf.Close()
			// patch the cryptex
			if err := ridiff.RawImagePatch("", cf.Name(), dcf.Name(), 0); err != nil {
				return "", fmt.Errorf("failed to patch %s: %v", filepath.Base(file.Path()), err)
			}
			return dcf.Name(), nil
		}
	}

	return "", fmt.Errorf("cryptex '%s' not found", cryptex)
}

func (r *Reader) ExtractFromCryptexes(pattern, output string) ([]string, error) {
	var out []string

	match, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile extract regex pattern '%s': %v", pattern, err)
	}

	tmpdir, err := os.MkdirTemp("", "ota_extract_cryptexes")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	for _, cryptex := range []string{"cryptex-system-(arm64e?|x86_64h?)$"} {
		re := regexp.MustCompile(cryptex)
		for _, file := range r.Files() {
			if re.MatchString(file.Name()) {
				cryptexFile, err := r.Open(file.Path(), false)
				if err != nil {
					return nil, fmt.Errorf("failed to open cryptex file: %v", err)
				}
				defer cryptexFile.Close()
				// create a temp file to hold the OTA cryptex
				cf, err := os.Create(filepath.Join(tmpdir, file.Name()))
				if err != nil {
					return nil, fmt.Errorf("failed to create file: %v", err)
				}
				// create a temp file to hold the PATCHED OTA cryptex DMG
				dcf, err := os.Create(filepath.Join(tmpdir, file.Name()+".dmg"))
				if err != nil {
					return nil, fmt.Errorf("failed to create file: %v", err)
				}
				if _, err := io.Copy(cf, cryptexFile); err != nil {
					return nil, fmt.Errorf("failed to write file: %v", err)
				}
				cf.Close()
				// patch the cryptex
				if err := ridiff.RawImagePatch("", cf.Name(), dcf.Name(), 0); err != nil {
					return nil, fmt.Errorf("failed to patch %s: %v", filepath.Base(file.Path()), err)
				}
				dcf.Close()
				// mount the patched cryptex
				utils.Indent(log.Info, 4)(fmt.Sprintf("Mounting DMG %s", dcf.Name()))
				mountPoint, alreadyMounted, err := utils.MountDMG(dcf.Name())
				if err != nil {
					return nil, fmt.Errorf("failed to IPSW FS dmg: %v", err)
				}
				if alreadyMounted {
					utils.Indent(log.Debug, 5)(fmt.Sprintf("%s already mounted", dcf.Name()))
				} else {
					defer func() {
						utils.Indent(log.Debug, 4)(fmt.Sprintf("Unmounting %s", dcf.Name()))
						if err := utils.Retry(3, 2*time.Second, func() error {
							return utils.Unmount(mountPoint, true)
						}); err != nil {
							log.Errorf("failed to unmount DMG %s at %s: %v", dcf.Name(), mountPoint, err)
						}
					}()
				}
				// extract files from the mounted cryptex
				if err := filepath.Walk(mountPoint, func(path string, info fs.FileInfo, err error) error {
					if err != nil {
						return fmt.Errorf("failed to walk %s: %v", path, err)
					}
					if info.IsDir() {
						return nil
					}
					if match.MatchString(path) {
						fname := filepath.Join(output, strings.TrimPrefix(path, mountPoint))
						if err := utils.MkdirAndCopy(path, fname); err != nil {
							return fmt.Errorf("failed to copy %s to %s: %v", path, fname, err)
						}
						out = append(out, fname)
					}
					return nil
				}); err != nil {
					if errors.Is(err, filepath.SkipDir) {
						break
					}
					return nil, fmt.Errorf("failed to read files in cryptex folder: %v", err)
				}
			}
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no files found matching pattern '%s'", pattern)
	}

	return out, nil
}

// Open opens the named file in the ZIP archive,
// using the semantics of fs.FS.Open:
// paths are always slash separated, with no
// leading / or ../ elements.
func (r *Reader) Open(name string, decomp bool) (fs.File, error) {
	r.initFileList()

	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	e := r.openLookup(name)
	if e == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	rc, err := e.Open(decomp)
	if err != nil {
		return nil, err
	}
	return rc.(fs.File), nil
}

func (r *Reader) OpenInPayload(name string) (fs.File, error) {
	if err := r.initPayloadMap(); err != nil {
		return nil, err
	}
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	payload := r.payloadLookuo(name)
	if payload == "" {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	rc, err := r.Open(payload, true)
	if err != nil {
		return nil, err
	}
	return rc, nil
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

func (r *Reader) payloadLookuo(name string) string {
	dir, elem, _ := split(name)
	startFiles := maps.Values(r.payloadMap)
	sort.Strings(startFiles)
	i := sort.Search(len(startFiles), func(i int) bool {
		idir, ielem, _ := split(startFiles[i])
		return idir > dir || idir == dir && ielem >= elem
	})
	if i < len(startFiles) {
		for k, v := range r.payloadMap {
			if k == startFiles[i] {
				return v
			}
		}
	}
	return ""
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

func (f *File) Open(decomp bool) (io.ReadCloser, error) {
	var mdata [4]byte
	var rc io.ReadCloser
	if f.zfile != nil {
		zf, err := f.zfile.Open()
		if err != nil {
			return nil, err
		}
		if _, err := zf.Read(mdata[:]); err != nil {
			if err == io.EOF {
				zf.Close()
				return f.zfile.Open()
			}
			return nil, err
		}
		zf.Close()
		switch magic.Magic(binary.BigEndian.Uint32(mdata[:])) {
		case magic.MagicPBZX:
			if decomp {
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
			}
			fallthrough
		default:
			zf.Close()
			return f.zfile.Open()
		}
	}

	if _, err := f.entry.Read(mdata[:]); err != nil {
		if err == io.EOF {
			rc = &otaReader{
				rc: io.NopCloser(bytes.NewReader([]byte{})),
				f:  f,
			}
			return rc, nil
		}
		return nil, err
	}
	switch magic.Magic(binary.BigEndian.Uint32(mdata[:])) {
	case magic.MagicPBZX:
		if decomp {
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
		}
		fallthrough
	default:
		edata := make([]byte, f.entry.Size)
		if _, err := f.entry.Read(edata); err != nil {
			return nil, err
		}
		rc = &otaReader{
			rc: io.NopCloser(bytes.NewReader(edata)),
			f:  f,
		}
		return rc, nil
	}
}
