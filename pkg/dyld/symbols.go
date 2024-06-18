package dyld

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

// ErrNoLocals is the error for a shared cache that has no LocalSymbolsOffset
var ErrNoLocals = errors.New("dyld shared cache does NOT contain local symbols info")

// ErrNoExportTrieInCache is the error for a shared cache that has no LocalSymbolsOffset
var ErrNoExportTrieInCache = errors.New("dyld shared cache does NOT contain export trie info")

// ErrNoExportTrieInMachO is the error for a shared cache that has no LocalSymbolsOffset
var ErrNoExportTrieInMachO = errors.New("dylib does NOT contain export trie info")
var ErrSymbolNotInExportTrie = errors.New("dylib does NOT contain symbolin export trie info")
var ErrSymbolNotInImage = errors.New("dylib does NOT contain symbol")
var ErrNoPrebuiltLoadersInCache = errors.New("dyld shared cache does NOT contain prebuilt loader info")

type symKind uint8

const (
	LOCAL symKind = iota
	PUBLIC
	EXPORT
	SYMTAB
	BIND
)

func (k symKind) String() string {
	switch k {
	case LOCAL:
		return "local"
	case PUBLIC:
		return "public"
	case EXPORT:
		return "export"
	case SYMTAB:
		return "symtab"
	case BIND:
		return "bind"
	default:
		return "unknown"
	}
}

type Symbol struct {
	Name    string  `json:"name,omitempty"`
	Image   string  `json:"image,omitempty"`
	Type    string  `json:"type,omitempty"`
	Address uint64  `json:"address,omitempty"`
	Regex   string  `json:"regex,omitempty"`
	Kind    symKind `json:"-"`
}

var symDarkAddrColor = color.New(color.Bold, color.FgBlue).SprintfFunc()
var symAddrColor = color.New(color.Bold, color.FgMagenta).SprintfFunc()
var symTypeColor = color.New(color.FgGreen).SprintfFunc()
var symNameColor = color.New(color.Bold).SprintFunc()
var symImageColor = color.New(color.Faint, color.FgHiWhite).SprintfFunc()

func (s Symbol) String(color bool) string {
	if color {
		if s.Address > 0 {
			return fmt.Sprintf("%s:\t%s\t%s\t%s",
				symAddrColor("%#09x", s.Address),
				symTypeColor("(%s|%s)", s.Kind, s.Type),
				symNameColor(s.Name),
				symImageColor(filepath.Base(s.Image)))
		}
		return fmt.Sprintf("%s:\t%s\t%s\t%s",
			symImageColor("%#09x", s.Address),
			symTypeColor("(%s|%s)", s.Kind, s.Type),
			symNameColor(s.Name),
			symImageColor(filepath.Base(s.Image)))
	}
	return fmt.Sprintf("%#09x:\t(%s|%s)\t%s\t%s", s.Address, s.Kind, s.Type, s.Name, filepath.Base(s.Image))
}

// ParseLocalSyms parses dyld's private symbols
func (f *File) ParseLocalSyms(dump bool) error {
	for _, image := range f.Images {
		if err := image.ParseLocalSymbols(dump); err != nil {
			return err
		}
	}
	return nil
}

// FindLocalSymForAddress returns the local symbol at a given address
func (f *File) FindLocalSymForAddress(addr uint64) *CacheLocalSymbol64 {
	for _, image := range f.Images {
		for _, sym := range image.LocalSymbols {
			if sym.Value == addr {
				return sym
			}
		}
	}
	return nil
}

// FindLocalSymbol returns the local symbol that matches name
func (f *File) FindLocalSymbol(name string) *CacheLocalSymbol64 {
	for _, image := range f.Images {
		if lsym, err := image.GetLocalSymbol(name); err == nil {
			return lsym
		}
	}
	return nil
}

func (f *File) GetExportTrieSymbols(i *CacheImage) ([]trie.TrieExport, error) {
	var eTrieAddr, eTrieSize uint64

	if i.CacheImageInfoExtra.ExportsTrieAddr > 0 {
		eTrieAddr = i.CacheImageInfoExtra.ExportsTrieAddr
		eTrieSize = uint64(i.CacheImageInfoExtra.ExportsTrieSize)
	} else {
		m, err := i.GetMacho()
		if err != nil {
			return nil, fmt.Errorf("failed to parse MachO for image %s: %v", filepath.Base(i.Name), err)
		}
		if m.DyldExportsTrie() != nil {
			syms, err := m.DyldExports()
			if err != nil {
				return nil, fmt.Errorf("failed to get export trie symbols for image %s: %v", filepath.Base(i.Name), err)
			}
			return syms, nil
		} else if m.DyldInfo() != nil {
			eTrieAddr, _ = i.GetVMAddress(uint64(m.DyldInfo().ExportOff))
			eTrieSize = uint64(m.DyldInfo().ExportSize)
		} else {
			return nil, fmt.Errorf("failed to get export trie data for image %s: %w", filepath.Base(i.Name), ErrNoExportTrieInMachO)
		}
	}

	eTrieOffset, err := i.GetOffset(eTrieAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get offset of export trie addr")
	}

	sr := io.NewSectionReader(i.cache.r[i.cuuid], 0, 1<<63-1)

	if _, err := sr.Seek(int64(eTrieOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to export trie offset in cache: %v", err)
	}

	exportTrie := make([]byte, eTrieSize)
	if err := binary.Read(sr, f.ByteOrder, &exportTrie); err != nil {
		return nil, fmt.Errorf("failed to read export trie data: %v", err)
	}

	syms, err := trie.ParseTrieExports(bytes.NewReader(exportTrie), i.LoadAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get export trie symbols for image %s: %v", filepath.Base(i.Name), err)
	}

	return syms, nil
}

// ParsePublicSymbols prints out all the exported symbols
func (f *File) ParsePublicSymbols(dump bool) error {
	for _, image := range f.Images {
		if err := image.ParsePublicSymbols(dump); err != nil {
			return err
		}
	}
	return nil
}

// FindPublicSymForAddress returns the public symbol at a given address
func (f *File) FindPublicSymForAddress(addr uint64) (*Symbol, error) {
	for _, image := range f.Images {
		for _, sym := range image.PublicSymbols {
			if sym.Address == addr {
				return sym, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to find public symbol for address %#x in shared cache", addr)
}

// FindPublicSymbol returns the public symbol for a given name
func (f *File) FindPublicSymbol(name string) (*Symbol, error) {
	for _, image := range f.Images {
		if sym, err := image.GetPublicSymbol(name); err == nil {
			return sym, nil
		}
	}
	return nil, fmt.Errorf("failed to find public symbol %s in shared cache", name)
}

func (f *File) GetSymbolAddress(name string) (uint64, *CacheImage, error) {
	// search the addr to symbol map cache
	for addr, sym := range f.AddressToSymbol {
		if name == sym {
			i, err := f.GetImageContainingVMAddr(addr)
			if err != nil {
				return 0, nil, err
			}
			return addr, i, nil
		}
	}
	// search each image
	for _, image := range f.Images {
		if lsym, err := image.GetLocalSymbol(name); err == nil {
			return lsym.Value, image, nil
		}
		if sym, err := image.GetPublicSymbol(name); err == nil {
			if sym.Address > 0 {
				return sym.Address, image, nil
			}
		}
	}

	return 0, nil, fmt.Errorf("failed to find symbol %s in shared cache", name)
}

func (f *File) GetSymbol(name string) (*Symbol, error) {
	// search each image
	for _, image := range f.Images {
		if lsym, err := image.GetLocalSymbol(name); err == nil {
			m, err := image.GetPartialMacho()
			if err != nil {
				return nil, err
			}
			var sec string
			if lsym.Sect > 0 && int(lsym.Sect) <= len(m.Sections) {
				sec = fmt.Sprintf("%s.%s", m.Sections[lsym.Sect-1].Seg, m.Sections[lsym.Sect-1].Name)
			}
			return &Symbol{
				Name:    lsym.Name,
				Address: lsym.Value,
				Type:    lsym.Type.String(sec),
				Image:   image.Name,
				Kind:    LOCAL,
			}, nil
		}
		if sym, err := image.GetPublicSymbol(name); err != nil {
			return sym, nil
		}
	}

	return nil, fmt.Errorf("failed to find symbol %s in shared cache", name)
}

func (f *File) FindExportedSymbol(symbolName string) (*trie.TrieExport, error) {
	for _, image := range f.Images {
		if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
			log.Debugf("Scanning Image: %s", image.Name)
			syms, err := f.GetExportTrieSymbols(image)
			if err != nil {
				return nil, err
			}
			for _, sym := range syms {
				if sym.Name == symbolName {
					sym.FoundInDylib = image.Name
					return &sym, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("symbol was not found in exports")
}

func (f *File) GetExportedSymbols(ctx context.Context, symbolName string) (<-chan *Symbol, error) {
	errs, _ := errgroup.WithContext(ctx)
	syms := make(chan *Symbol, 1)

	if f.SupportsDylibPrebuiltLoader() {
		errs.Go(func() error {
			for _, image := range f.Images {
				pbl, err := f.GetDylibPrebuiltLoader(image.Name)
				if err != nil {
					return fmt.Errorf("failed to get prebuilt loader for %s: %s", image.Name, err)
				}
				uuid, off, err := f.GetOffset(image.LoadAddress + pbl.ExportsTrieLoaderOffset)
				if err != nil {
					return fmt.Errorf("failed to get ExportsTrie offset for %s: %s", image.Name, err)
				}
				data, err := f.ReadBytesForUUID(uuid, int64(off), uint64(pbl.ExportsTrieLoaderSize))
				if err != nil {
					return fmt.Errorf("failed to read ExportsTrie data for %s: %s", image.Name, err)
				}
				r := bytes.NewReader(data)
				if _, err := trie.WalkTrie(r, symbolName); err == nil {
					sym, err := trie.ReadExport(r, symbolName, image.LoadAddress)
					if err != nil {
						return fmt.Errorf("failed to read export for %s: %s", image.Name, err)
					}
					syms <- &Symbol{
						Name:    sym.Name,
						Address: sym.Address,
						Type:    sym.Type(),
						Image:   image.Name,
					}
				}
			}
			close(syms)
			return nil
		})
		return syms, errs.Wait()
	}

	return nil, ErrNoPrebuiltLoadersInCache
}

func (f *File) DumpStubIslands() error {
	if len(f.islandStubs) == 0 {
		if err := f.ParseStubIslands(); err != nil {
			return fmt.Errorf("failed to parse stub islands: %v", err)
		}
	}
	for stub, target := range f.islandStubs {
		if symName, ok := f.AddressToSymbol[target]; ok {
			fmt.Printf("%#x: %s\n", stub, symName)
		} else {
			fmt.Printf("%#x: %#x\n", stub, target)
		}
	}
	return nil
}

func (f *File) GetStubIslands() (map[uint64]string, error) {
	stubs := make(map[uint64]string)
	if len(f.islandStubs) == 0 {
		if err := f.ParseStubIslands(); err != nil {
			return nil, fmt.Errorf("failed to parse stub islands: %v", err)
		}
	}
	for stub, target := range f.islandStubs {
		if symName, ok := f.AddressToSymbol[target]; ok {
			stubs[stub] = symName
		}
	}
	return stubs, nil
}

// OpenOrCreateA2SCache returns an address to symbol map if the cache file exists otherwise it will create a NEW one
func (f *File) OpenOrCreateA2SCache(cacheFile string) error {
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		log.Info("parsing public symbols...")
		if err := f.ParsePublicSymbols(false); err != nil {
			utils.Indent(log.Warn, 2)(fmt.Sprintf("failed to parse all exported symbols: %v", err))
		}
		log.Info("parsing private symbols...")
		if err = f.ParseLocalSyms(false); err != nil {
			if errors.Is(err, ErrNoLocals) {
				utils.Indent(log.Warn, 2)("cache does NOT contain local symbols")
			} else {
				return err
			}
		}
		if f.Headers[f.UUID].CacheType == CacheTypeUniversal {
			log.Info("parsing stub islands...")
			if err := f.ParseStubIslands(); err != nil {
				return fmt.Errorf("failed to parse stub islands: %v", err)
			}
			for stub, target := range f.islandStubs {
				if symName, ok := f.AddressToSymbol[target]; ok {
					if !strings.HasPrefix(symName, "j_") {
						f.AddressToSymbol[stub] = "j_" + strings.TrimPrefix(symName, "__stub_helper.")
					} else {
						f.AddressToSymbol[stub] = symName
					}
				}
			}
		}
		log.Info("parsing objc info...")
		if err := f.ParseAllObjc(); err != nil {
			utils.Indent(log.Error, 2)(fmt.Sprintf("failed to parse objc info: %v: Continuing on without it...", err))
		}
		return f.SaveAddrToSymMap(cacheFile)
	}

	a2sFile, err := os.Open(cacheFile)
	if err != nil {
		return err
	}

	log.Infof("Loading symbol cache file...")
	// gzr, err := gzip.NewReader(a2sFile)
	// if err != nil {
	// 	return fmt.Errorf("failed to create gzip reader: %v", err)
	// }
	// Decoding the serialized data
	// err = gob.NewDecoder(gzr).Decode(&f.AddressToSymbol)
	err = gob.NewDecoder(a2sFile).Decode(&f.AddressToSymbol)
	if err != nil {
		return err
	}
	// gzr.Close()
	a2sFile.Close()

	f.symCacheLoaded = true

	return nil
}

// SaveAddrToSymMap saves the dyld address-to-symbol map to disk
func (f *File) SaveAddrToSymMap(dest string) error {
	var err error
	var of *os.File

	buff := new(bytes.Buffer)

	of, err = os.Create(dest)
	if errors.Is(err, os.ErrPermission) {
		var e *os.PathError
		if errors.As(err, &e) {
			log.Errorf("failed to create address to symbol cache file %s (%v)", e.Path, e.Err)
		}
		tmpDir := os.TempDir()
		if runtime.GOOS == "darwin" {
			tmpDir = "/tmp"
		}
		tempa2sfile := filepath.Join(tmpDir, f.UUID.String()+".a2s")
		of, err = os.Create(tempa2sfile)
		if err != nil {
			return err
		}
		utils.Indent(log.Warn, 2)("creating in the temp folder")
		utils.Indent(log.Warn, 3)(fmt.Sprintf("to use in the future you must supply the flag: --cache %s ", tempa2sfile))
	} else if err != nil {
		return err
	}
	defer of.Close()

	e := gob.NewEncoder(buff)

	// Encoding the map
	err = e.Encode(f.AddressToSymbol)
	if err != nil {
		return fmt.Errorf("failed to encode addr2sym map to binary: %v", err)
	}

	// gzw := gzip.NewWriter(of)
	// defer gzw.Close()

	// _, err = buff.WriteTo(gzw)
	_, err = buff.WriteTo(of)
	if err != nil {
		return fmt.Errorf("failed to write addr2sym map to gzip file: %v", err)
	}

	return nil
}

// GetCString returns a c-string at a given virtual address
func (f *File) GetCString(strVMAdr uint64) (string, error) {

	uuid, strOffset, err := f.GetOffset(strVMAdr)
	if err != nil {
		return "", err
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	if _, err := sr.Seek(int64(strOffset), io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to Seek to offset %#x: %v", strOffset, err)
	}

	s, err := bufio.NewReader(sr).ReadString('\x00')
	if err != nil {
		return "", fmt.Errorf("failed to ReadString as offset %#x, %v", strOffset, err)
	}

	if len(s) > 0 {
		return strings.Trim(s, "\x00"), nil
	}

	return "", fmt.Errorf("string not found at offset %#x", strOffset)
}

// GetCStringAtOffsetForUUID returns a c-string at a given offset
func (f *File) GetCStringAtOffsetForUUID(uuid types.UUID, offset uint64) (string, error) {
	sr := io.NewSectionReader(f.r[uuid], int64(offset), 1<<63-1)

	s, err := bufio.NewReader(sr).ReadString('\x00')
	if err != nil {
		return "", fmt.Errorf("failed to ReadString as offset %#x, %v", offset, err)
	}

	if len(s) > 0 {
		return strings.Trim(s, "\x00"), nil
	}

	return "", fmt.Errorf("string not found at offset %#x", offset)
}
