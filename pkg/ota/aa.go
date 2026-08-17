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
	"golang.org/x/sys/execabs"
)

// ErrCryptexNotFound is returned by ExtractCryptex when the OTA
// does not contain a matching cryptex member.
var ErrCryptexNotFound = errors.New("cryptex not found")

var (
	reOTADeviceTreeIm4p = regexp.MustCompile(`.*DeviceTree.*im4p$`)
	reOTAInfoPlist      = regexp.MustCompile(`^Info\.plist$`)
	reOTAAssetDataInfo  = regexp.MustCompile(`^AssetData/Info\.plist$`)
	reOTARestorePlist   = regexp.MustCompile(`Restore\.plist$`)
	reOTABuildManifest  = regexp.MustCompile(`BuildManifest\.plist$`)
	reOTASystemVersion  = regexp.MustCompile(`SystemVersion\.plist$`)
	reOTADscCryptex     = regexp.MustCompile(`^cryptex-system-(arm64(_32|e)?|x86_64h?|rosetta)$`)
	// reAnySystemCryptex selects a system cryptex when the caller named no
	// architecture. arm64_32 must be present: `arm64e?` cannot match it, so a
	// watchOS OTA carrying only cryptex-system-arm64_32 would otherwise report
	// "cryptex not found" unless the arch was passed explicitly.
	reAnySystemCryptex = regexp.MustCompile(`cryptex-system-(arm64(_32|e)?|x86_64h?)$`)
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

// Config holds optional configuration for opening OTA files
type Config struct {
	// SymmetricKey is the base64-encoded AEA symmetric encryption key
	SymmetricKey string
	// Proxy to use when fetching AEA keys
	Proxy string
	// Insecure allows insecure connections when fetching AEA keys
	Insecure bool
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

// Open opens an OTA file with optional configuration
// If conf is nil, default configuration is used (automatic key lookup)
func Open(name string, conf *Config) (*AA, error) {
	// Use default config if nil
	if conf == nil {
		conf = &Config{}
	}

	if isAEA, err := magic.IsAEA(name); err != nil {
		return nil, err
	} else if isAEA { // check if file is AEA encrypted
		var key string
		if conf.SymmetricKey != "" {
			key = conf.SymmetricKey
		} else {
			// Try to get key from filename (legacy behavior)
			if keyFromName, err := getKeyFromName(name); err != nil {
				// No key in filename - explicitly set empty to trigger automatic lookup
				key = ""
				log.Debug("No key in filename, will attempt automatic key lookup from AEA metadata")
			} else {
				key = keyFromName
			}
		}
		// Call aea.Decrypt - if key is empty, it will attempt automatic lookup from AEA metadata
		name, err = aea.Decrypt(&aea.DecryptConfig{
			Input:     name,
			Output:    os.TempDir(),
			B64SymKey: key,
			Proxy:     conf.Proxy,
			Insecure:  conf.Insecure,
		})
		if err != nil {
			return nil, wrapPhase(PhaseAEADecrypt, "", fmt.Errorf("failed to decrypt AEA: %v (try providing --key-val, --key-db, or ensure you're online for automatic key lookup)", err))
		}
		defer os.Remove(name)
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, wrapPhase(PhaseOTAOpen, "", err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, wrapPhase(PhaseOTAOpen, "", err)
	}
	r := new(AA)
	if r.isZip, err = magic.IsZip(name); err != nil {
		f.Close()
		return nil, wrapPhase(PhaseOTAOpen, "", err)
	} else if r.isZip { // check if file is a zip
		r.isZip = true
		if err = r.initZip(f, fi.Size()); err != nil {
			f.Close()
			return nil, wrapPhase(PhaseOTAOpen, "", err)
		}
	} else {
		if err = r.init(f, fi.Size()); err != nil {
			f.Close()
			return nil, wrapPhase(PhaseOTAOpen, "", err)
		}
	}
	r.f = f
	return r, err
}

func (a *AA) Info() (*info.Info, error) {
	var pfiles []fs.File
	for _, file := range a.Files() {
		switch {
		case reOTADeviceTreeIm4p.MatchString(file.Name()):
			fallthrough
		case reOTAInfoPlist.MatchString(file.Name()):
			fallthrough
		case reOTAAssetDataInfo.MatchString(file.Name()):
			fallthrough
		case reOTARestorePlist.MatchString(file.Name()):
			fallthrough
		case reOTABuildManifest.MatchString(file.Name()):
			fallthrough
		case reOTASystemVersion.MatchString(file.Name()):
			f, err := a.Open(file.Name(), true)
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
			if pre.MatchString(file.Base()) {
				f, err := r.Open(file.Name(), false)
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

// GetPayloadFiles extracts every file matching pattern from the OTA's
// payloadv2 members into output.
//
// It exists to keep the pre-callback signature compiling for downstream Go
// consumers. New callers that need the destination path of each materialized
// file should use [Reader.GetPayloadFilesWithCallback] instead.
func (r *Reader) GetPayloadFiles(pattern, payloadRange, output string) error {
	return r.GetPayloadFilesWithCallback(pattern, payloadRange, output, nil)
}

// GetPayloadFilesWithCallback extracts every file matching pattern from the
// OTA's payloadv2 members into output. onFile, when non-nil, is called with the
// destination path of each materialized file; callers extracting the entire
// filesystem pass nil to avoid accumulating one string per OTA member.
func (r *Reader) GetPayloadFilesWithCallback(pattern, payloadRange, output string, onFile func(dst string)) error {
	r.initFileList()
	pre := regexp.MustCompile(`^payload.\d+$`)
	if payloadRange != "" {
		// payloadRange comes straight from --range, so it must never panic.
		var err error
		if pre, err = regexp.Compile(payloadRange); err != nil {
			return wrapPhase(PhasePayloadExtract, "",
				fmt.Errorf("failed to compile payload range regex '%s': %w", payloadRange, err))
		}
	}
	var errs []error
	for _, file := range r.Files() {
		if file.isDir || !pre.MatchString(file.Base()) {
			continue
		}
		if err := r.getPayloadFile(file, pattern, output, onFile); err != nil {
			errs = append(errs, wrapPhase(PhasePayloadExtract, file.Base(), err))
		}
	}
	return errors.Join(errs...)
}

func (r *Reader) getPayloadFile(file *File, pattern, output string, onFile func(dst string)) (err error) {
	tmpdir, err := r.extractPayloadToTemp(file, pattern)
	if err != nil {
		return err
	}
	defer func() { err = joinRemoveTempDir(err, file.Base(), tmpdir) }()

	if err := filepath.Walk(tmpdir, func(path string, fi os.FileInfo, werr error) error {
		if werr != nil || fi.IsDir() {
			return werr
		}
		fname, err := movePayloadFile(tmpdir, output, path)
		if err != nil {
			return err
		}
		utils.Indent(log.Info, 2)(fmt.Sprintf("Extracting from '%s' -> %s\t%s", file.Base(), humanize.Bytes(uint64(fi.Size())), fname))
		if onFile != nil {
			onFile(fname)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to read files in tmp folder: %w", err)
	}
	return nil
}

// extractPayloadToTemp unpacks the parts of a payloadv2 member matching
// pattern into a new temp dir the caller owns.
func (r *Reader) extractPayloadToTemp(file *File, pattern string) (string, error) {
	f, err := r.Open(file.Name(), false)
	if err != nil {
		return "", err
	}
	tmpdir, err := os.MkdirTemp("", "ota_payload_extract")
	if err != nil {
		_ = f.Close()
		return "", err
	}
	// On these paths the staging dir is abandoned, so a failed removal leaks it.
	// Cleanup is part of the report contract, so keep both failures.
	if err := aaExtractPattern(f, pattern, tmpdir); err != nil {
		_ = f.Close()
		return "", joinRemoveTempDir(err, file.Base(), tmpdir)
	}
	if err := f.Close(); err != nil {
		return "", joinRemoveTempDir(err, file.Base(), tmpdir)
	}
	return tmpdir, nil
}

func movePayloadFile(tmpdir, output, path string) (string, error) {
	rel, err := filepath.Rel(tmpdir, path)
	if err != nil {
		return "", fmt.Errorf("failed to compute relative path for %s: %v", path, err)
	}
	fname, err := utils.SanitizeArchivePath(output, rel)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(fname), 0o750); err != nil {
		return "", fmt.Errorf("failed to create dir %s: %v", filepath.Dir(fname), err)
	}
	if err := os.Rename(path, fname); err != nil {
		return "", fmt.Errorf("failed to mv file %s to %s: %v", rel, fname, err)
	}
	return fname, nil
}

func (r *Reader) PayloadFiles(pattern string, json bool) error {
	r.initFileList()
	pre := regexp.MustCompile(`^payload.\d+$`)
	for _, file := range r.Files() {
		if file.isDir {
			continue
		}
		if pre.MatchString(file.Base()) {
			f, err := r.Open(file.Name(), false)
			if err != nil {
				return err
			}
			out, err := aaList(f, pattern, json)
			if closeErr := f.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			if err != nil {
				return err
			}
			if len(out) > 0 && out != "[]" {
				fmt.Println(out)
			}
		}
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
	// Directory entries are not materialized into the destination: the caller
	// walks files and creates their parents itself. Excluding them here also
	// prevents archived directory modes without a search bit (for example 0600)
	// from making the staging tree impossible to walk or remove.
	cmd := exec.Command(aaPath, "extract", "-d", output, "-include-regex", pattern, "-exclude-type", "d")
	cmd.Stdin = in
	// aa exits 0 when the regex simply matches nothing, so any non-zero status
	// is a real failure. Suppressing it would let a failed payload member
	// vanish from the report and leave `complete` claiming otherwise.
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("aa extract failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ExtractCryptex patches the named cryptex member into a mountable DMG under
// output and returns its path. A failure to remove the staging directory is
// joined onto the result, matching the dyld_shared_cache sources: a leaked
// temp dir means the operation did not finish cleanly.
func (r *Reader) ExtractCryptex(cryptex, output string) (dmg string, err error) {
	var re *regexp.Regexp
	switch cryptex {
	case "system":
		re = reAnySystemCryptex
	case "system-arm64e":
		re = regexp.MustCompile(`cryptex-system-arm64e$`)
	case "system-x86_64h":
		re = regexp.MustCompile(`cryptex-system-x86_64h$`)
	case "app":
		re = regexp.MustCompile(`cryptex-app$`)
	default:
		return "", fmt.Errorf("unknown cryptex type '%s'", cryptex)
	}

	tmpdir, err := os.MkdirTemp("", "ota_extract_cryptexes")
	if err != nil {
		return "", wrapPhase(PhaseOutputSetup, "", fmt.Errorf("failed to create temp dir: %w", err))
	}
	defer func() { err = joinRemoveTempDir(err, "", tmpdir) }()

	for _, file := range r.Files() {
		if re.MatchString(file.Base()) {
			cryptexFile, err := r.Open(file.Name(), false)
			if err != nil {
				return "", fmt.Errorf("failed to open cryptex file: %v", err)
			}
			defer cryptexFile.Close()
			// create a temp file to hold the OTA cryptex
			cf, err := os.Create(filepath.Join(tmpdir, file.Base()))
			if err != nil {
				return "", fmt.Errorf("failed to create file: %v", err)
			}
			// create a temp file to hold the PATCHED OTA cryptex DMG
			dcf, err := os.Create(filepath.Join(output, file.Base()+".dmg"))
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
				return "", fmt.Errorf("failed to patch %s: %v", filepath.Base(file.Name()), err)
			}
			return dcf.Name(), nil
		}
	}

	return "", fmt.Errorf("%w: '%s'", ErrCryptexNotFound, cryptex)
}

// ExtractFromCryptexes extracts every file matching pattern from the OTA's
// dyld_shared_cache cryptex members and returns their destination paths.
//
// It exists to keep the pre-attribution signature compiling for downstream Go
// consumers. New callers that need to know which cryptex each file came from
// should use [Reader.ExtractFromCryptexesWithSources] instead.
func (r *Reader) ExtractFromCryptexes(pattern, output string) ([]string, error) {
	return extractedPaths(r.ExtractFromCryptexesWithSources(pattern, output))
}

// extractedPaths flattens an extraction result to its destination paths.
//
// It converts before inspecting err because a non-empty result alongside a
// non-nil error is load-bearing: a cryptex can fail to mount, unmount or walk
// after another already wrote caches to disk, so `if err != nil { return nil,
// err }` would discard files that exist and are valid. nil is returned for an
// empty result so callers comparing against nil behave as they always have.
func extractedPaths(files []ExtractedFile, err error) ([]string, error) {
	if len(files) == 0 {
		return nil, err
	}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	return paths, err
}

// ExtractFromCryptexesWithSources extracts every file matching pattern from the
// OTA's dyld_shared_cache cryptex members, pairing each destination path with
// the cryptex member it came from. It returns ErrNoDscInCryptexes when the OTA
// carries no matching cryptex content, which means the source does not apply
// rather than that it failed.
func (r *Reader) ExtractFromCryptexesWithSources(pattern, output string) (files []ExtractedFile, err error) {
	return r.ExtractFromCryptexesWithSourcesForArches(pattern, output, nil)
}

// ExtractFromCryptexesWithSourcesForArches is the architecture-filtered form
// of [Reader.ExtractFromCryptexesWithSources]. It skips cryptex members that
// cannot carry any requested cache family before staging or mounting them.
// An empty arches slice preserves the all-cryptex behavior.
func (r *Reader) ExtractFromCryptexesWithSourcesForArches(pattern, output string, arches []string) (files []ExtractedFile, err error) {
	match, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile extract regex pattern '%s': %v", pattern, err)
	}

	tmpdir, err := os.MkdirTemp("", "ota_extract_cryptexes")
	if err != nil {
		return nil, wrapPhase(PhaseOutputSetup, "", fmt.Errorf("failed to create temp dir: %w", err))
	}
	defer func() { err = joinRemoveTempDir(err, "", tmpdir) }()

	out, err := extractFromDscCryptexFilesForArches(r.Files(), arches, func(file *File) ([]string, error) {
		return r.extractFromCryptexFile(file, match, tmpdir, output)
	})
	if err != nil {
		return out, err
	}
	if len(out) == 0 {
		return nil, ErrNoDscInCryptexes
	}
	return out, nil
}

func extractFromDscCryptexFiles(files []*File, extract func(*File) ([]string, error)) ([]ExtractedFile, error) {
	return extractFromDscCryptexFilesForArches(files, nil, extract)
}

func extractFromDscCryptexFilesForArches(files []*File, arches []string, extract func(*File) ([]string, error)) ([]ExtractedFile, error) {
	var out []ExtractedFile
	var extractErrs []error

	for _, file := range files {
		if !reOTADscCryptex.MatchString(file.Base()) || !cryptexMatchesArches(file.Base(), arches) {
			continue
		}
		extracted, err := extract(file)
		for _, path := range extracted {
			out = append(out, ExtractedFile{Path: path, Source: file.Base()})
		}
		if err != nil {
			extractErrs = append(extractErrs, wrapPhase(PhaseCryptexDiscovery, file.Base(), err))
		}
	}

	return out, errors.Join(extractErrs...)
}

// cryptexMatchesArches reports whether a cryptex member can carry at least one
// requested cache family. Rosetta cryptexes can carry x86_64, x86_64h and AOT
// caches; older OTAs can name the x86 cryptex directly.
func cryptexMatchesArches(source string, arches []string) bool {
	if len(arches) == 0 {
		return true
	}
	sourceArch := strings.TrimPrefix(source, "cryptex-system-")
	for _, arch := range arches {
		switch arch {
		case "aot":
			if sourceArch == "rosetta" || sourceArch == "x86_64" || sourceArch == "x86_64h" {
				return true
			}
		case "x86_64", "x86_64h":
			if sourceArch == arch || sourceArch == "rosetta" {
				return true
			}
		default:
			if sourceArch == arch {
				return true
			}
		}
	}
	return false
}

func (r *Reader) extractFromCryptexFile(file *File, match *regexp.Regexp, tmpdir, output string) (out []string, err error) {
	dmg, err := r.stageCryptexDMG(file, tmpdir)
	if err != nil {
		return nil, err
	}

	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting DMG %s", dmg))
	mountPoint, alreadyMounted, err := utils.MountDMG(dmg, "")
	if err != nil {
		return nil, wrapPhase(PhaseMount, file.Base(), fmt.Errorf("failed to mount cryptex DMG %s: %w", dmg, err))
	}
	// Detach only what this invocation attached. A pre-existing attachment
	// belongs to another process -- on Linux the mount point is derived from
	// the DMG basename alone, so a concurrent run shares it and would have its
	// filesystem yanked out from under an in-progress walk.
	if alreadyMounted {
		utils.Indent(log.Warn, 2)(fmt.Sprintf(
			"%s was already mounted at %s; leaving it attached", dmg, mountPoint))
	} else {
		defer func() {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting %s", dmg))
			if uerr := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, true)
			}); uerr != nil {
				err = errors.Join(err, wrapPhase(PhaseCleanup, file.Base(),
					fmt.Errorf("failed to unmount DMG %s at %s: %v", dmg, mountPoint, uerr)))
			}
		}()
	}

	return copyMatchesFromMount(file, match, mountPoint, output)
}

// copyMatchesFromMount copies every file under mountPoint matching match into
// output, preserving the mount-relative directory structure. It keeps walking
// past an unreadable entry so one bad subtree cannot discard the files already
// copied, but it reports every such entry: an untraversed subtree is not proof
// that it held no caches.
func copyMatchesFromMount(file *File, match *regexp.Regexp, mountPoint, output string) ([]string, error) {
	var out []string
	var walkErrs []error
	if err := filepath.Walk(mountPoint, func(path string, info fs.FileInfo, werr error) error {
		if werr != nil {
			utils.Indent(log.Warn, 3)(fmt.Sprintf("failed to walk %s: %v", path, werr))
			walkErrs = append(walkErrs, wrapPhase(PhaseDSCDiscovery, file.Base(),
				fmt.Errorf("failed to walk %s: %w", path, werr)))
			return nil
		}
		if info.IsDir() || !match.MatchString(path) {
			return nil
		}
		fname := filepath.Join(output, strings.TrimPrefix(path, mountPoint))
		if cerr := utils.MkdirAndCopy(path, fname); cerr != nil {
			return wrapPhase(PhaseCopy, file.Base(), fmt.Errorf("failed to copy %s to %s: %v", path, fname, cerr))
		}
		out = append(out, fname)
		return nil
	}); err != nil {
		// %w, not %v: the walk closure already classifies its own failures
		// (PhaseCopy), and flattening the chain here would silently relabel
		// them with the PhaseDSCDiscovery default.
		return out, wrapPhase(PhaseDSCDiscovery, file.Base(),
			fmt.Errorf("failed to read files in cryptex folder: %w", err))
	}
	return out, errors.Join(walkErrs...)
}

// stageCryptexDMG copies the OTA cryptex member into tmpdir and RIDIFF-patches
// it into a mountable DMG, returning the patched DMG path.
func (r *Reader) stageCryptexDMG(file *File, tmpdir string) (string, error) {
	cryptexFile, err := r.Open(file.Name(), false)
	if err != nil {
		return "", wrapPhase(PhaseCopy, file.Base(), fmt.Errorf("failed to open cryptex file: %v", err))
	}
	defer cryptexFile.Close()

	cf, err := os.Create(filepath.Join(tmpdir, file.Base()))
	if err != nil {
		return "", wrapPhase(PhaseCopy, file.Base(), fmt.Errorf("failed to create file: %v", err))
	}
	if _, err := io.Copy(cf, cryptexFile); err != nil {
		_ = cf.Close()
		return "", wrapPhase(PhaseCopy, file.Base(), fmt.Errorf("failed to write file: %v", err))
	}
	if err := cf.Close(); err != nil {
		return "", wrapPhase(PhaseCopy, file.Base(), fmt.Errorf("failed to close cryptex file: %v", err))
	}

	dcf, err := os.Create(filepath.Join(tmpdir, file.Base()+".dmg"))
	if err != nil {
		return "", wrapPhase(PhaseCopy, file.Base(), fmt.Errorf("failed to create file: %v", err))
	}
	if err := dcf.Close(); err != nil {
		return "", wrapPhase(PhaseCopy, file.Base(), fmt.Errorf("failed to close patched cryptex file: %v", err))
	}
	if err := ridiff.RawImagePatch("", cf.Name(), dcf.Name(), 0); err != nil {
		return "", wrapPhase(PhaseCryptexPatch, file.Base(),
			fmt.Errorf("failed to patch %s: %v", filepath.Base(file.Name()), err))
	}
	return dcf.Name(), nil
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

func (f *File) Base() string { _, elem, _ := split(f.name); return elem }
func (f *File) Name() string { return f.name }
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
			zf.Close()
			if err == io.EOF {
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
				defer zf.Close()
				if err := pbzx.Extract(context.Background(), zf, &pbuf, runtime.NumCPU()); err != nil {
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
