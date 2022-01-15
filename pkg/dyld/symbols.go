package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

// ErrNoLocals is the error for a shared cache that has no LocalSymbolsOffset
var ErrNoLocals = errors.New("dyld shared cache does NOT contain local symbols info")

// ErrNoExportTrieInCache is the error for a shared cache that has no LocalSymbolsOffset
var ErrNoExportTrieInCache = errors.New("dyld shared cache does NOT contain export trie info")

// ErrNoExportTrieInMachO is the error for a shared cache that has no LocalSymbolsOffset
var ErrNoExportTrieInMachO = errors.New("dylib does NOT contain export trie info")
var ErrSymbolNotInExportTrie = errors.New("dylib does NOT contain symbolin export trie info")
var ErrSymbolNotInImage = errors.New("dylib does NOT contain symbol")

// ParseLocalSyms parses dyld's private symbols
func (f *File) ParseLocalSyms() error {

	var uuid types.UUID

	if f.IsDyld4 {
		uuid = f.symUUID
	} else {
		uuid = f.UUID
	}

	if f.Headers[uuid].LocalSymbolsOffset == 0 {
		return fmt.Errorf("failed to parse local syms: %w", ErrNoLocals)
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	stringPool := io.NewSectionReader(f.r[uuid], int64(f.LocalSymInfo.StringsFileOffset), int64(f.LocalSymInfo.StringsSize))
	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), io.SeekStart)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {
			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return err
			}
			stringPool.Seek(int64(nlist.Name), io.SeekStart)
			s, err := bufio.NewReader(stringPool).ReadString('\x00')
			if err != nil {
				return fmt.Errorf("failed to read string at: %#x; %v", f.LocalSymInfo.StringsFileOffset+nlist.Name, err)
			}
			f.AddressToSymbol[nlist.Value] = strings.Trim(s, "\x00")
			f.Images[idx].LocalSymbols = append(f.Images[idx].LocalSymbols, &CacheLocalSymbol64{
				Name:    strings.Trim(s, "\x00"),
				Nlist64: nlist,
			})
		}
	}

	return nil
}

func (f *File) GetLocalSymbolsForImage(image *CacheImage) error {

	if !image.Analysis.State.IsPrivatesDone() {

		var uuid types.UUID

		if f.IsDyld4 {
			uuid = f.symUUID
		} else {
			uuid = f.UUID
		}

		if f.Headers[uuid].LocalSymbolsOffset == 0 {
			image.Analysis.State.SetPrivates(true) // TODO: does this have any bad side-effects ?
			return fmt.Errorf("failed to parse local syms for image %s: %w", image.Name, ErrNoLocals)
		}

		sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

		stringPool := io.NewSectionReader(sr, int64(f.LocalSymInfo.StringsFileOffset), int64(f.LocalSymInfo.StringsSize))
		sr.Seek(int64(f.LocalSymInfo.NListFileOffset), io.SeekStart)

		for idx := uint32(0); idx < f.LocalSymInfo.EntriesCount; idx++ {
			// skip over other images
			if idx != image.Index {
				sr.Seek(int64(int(f.Images[idx].NlistCount)*binary.Size(types.Nlist64{})), os.SEEK_CUR)
				continue
			}

			for e := 0; e < int(f.Images[idx].NlistCount); e++ {

				nlist := types.Nlist64{}
				if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
					return err
				}

				stringPool.Seek(int64(nlist.Name), io.SeekStart)
				s, err := bufio.NewReader(stringPool).ReadString('\x00')
				if err != nil {
					log.Error(errors.Wrapf(err, "failed to read string at: %d", f.LocalSymInfo.StringsFileOffset+nlist.Name).Error())
				}

				f.AddressToSymbol[nlist.Value] = strings.Trim(s, "\x00")
				f.Images[idx].LocalSymbols = append(f.Images[idx].LocalSymbols, &CacheLocalSymbol64{
					Name:    f.AddressToSymbol[nlist.Value],
					Nlist64: nlist,
				})
			}

			image.Analysis.State.SetPrivates(true)
			return nil
		}
	}

	return nil
}

func (f *File) FindLocalSymbol(symbol string) (*CacheLocalSymbol64, error) {

	var uuid types.UUID

	if f.IsDyld4 {
		uuid = f.symUUID
	} else {
		uuid = f.UUID
	}

	if f.Headers[uuid].LocalSymbolsOffset == 0 {
		return nil, fmt.Errorf("failed to parse local symbol %s: %w", symbol, ErrNoLocals)
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	sr.Seek(int64(uint32(f.Headers[uuid].LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), io.SeekStart)
	stringPool := make([]byte, f.LocalSymInfo.StringsSize)
	sr.ReadAt(stringPool, int64(f.LocalSymInfo.StringsFileOffset))
	nlistName := bytes.Index(stringPool, []byte(symbol))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), io.SeekStart)
	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {
			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return nil, err
			}
			if int(nlist.Name) == nlistName {
				return &CacheLocalSymbol64{
					Name:         symbol,
					FoundInDylib: f.Images[idx].Name,
					Nlist64:      nlist,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("symbol not found in private symbols")
}

func (f *File) FindLocalSymbolInImage(symbol, imageName string) (*CacheLocalSymbol64, error) {

	var uuid types.UUID

	if f.IsDyld4 {
		uuid = f.symUUID
	} else {
		uuid = f.UUID
	}

	if f.Headers[uuid].LocalSymbolsOffset == 0 {
		return nil, fmt.Errorf("failed to parse local symbol %s in image %s: %w", symbol, imageName, ErrNoLocals)
	}

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	image, err := f.Image(imageName)
	if err != nil {
		return nil, err
	}

	sr.Seek(int64(uint32(f.Headers[uuid].LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), io.SeekStart)

	stringPool := make([]byte, f.LocalSymInfo.StringsSize)
	sr.ReadAt(stringPool, int64(f.LocalSymInfo.StringsFileOffset))

	nlistName := bytes.Index(stringPool, []byte(symbol))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), io.SeekStart)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		// skip over other images
		if uint32(idx) != image.Index {
			sr.Seek(int64(int(f.Images[idx].NlistCount)*binary.Size(types.Nlist64{})), os.SEEK_CUR)
			continue
		}
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {
			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return nil, err
			}
			if int(nlist.Name) == nlistName {
				return &CacheLocalSymbol64{
					Name:         symbol,
					FoundInDylib: f.Images[idx].Name,
					Nlist64:      nlist,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("symbol not found in private symbols")
}

// GetLocalSymAtAddress returns the local symbol at a given address
func (f *File) GetLocalSymAtAddress(addr uint64) *CacheLocalSymbol64 {
	for _, image := range f.Images {
		for _, sym := range image.LocalSymbols {
			if sym.Value == addr {
				return sym
			}
		}
	}
	return nil
}

// GetLocalSymbol returns the local symbol that matches name
func (f *File) GetLocalSymbol(symbolName string) *CacheLocalSymbol64 {
	for _, image := range f.Images {
		for _, sym := range image.LocalSymbols {
			if sym.Name == symbolName {
				sym.FoundInDylib = image.Name
				return sym
			}
		}
	}
	return nil
}

// GetLocalSymbolInImage returns the local symbol that matches name in a given image
func (f *File) GetLocalSymbolInImage(imageName, symbolName string) *CacheLocalSymbol64 {
	image, err := f.Image(imageName)
	if err != nil {
		return nil
	}
	for _, sym := range image.LocalSymbols {
		if sym.Name == symbolName {
			return sym
		}
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
		return "", fmt.Errorf("failed to Seek to offset 0x%x: %v", strOffset, err)
	}

	s, err := bufio.NewReader(sr).ReadString('\x00')
	if err != nil {
		return "", fmt.Errorf("failed to ReadString as offset 0x%x, %v", strOffset, err)
	}

	if len(s) > 0 {
		return strings.Trim(s, "\x00"), nil
	}

	return "", fmt.Errorf("string not found at offset 0x%x", strOffset)
}

// GetCStringAtOffsetForUUID returns a c-string at a given offset
func (f *File) GetCStringAtOffsetForUUID(uuid types.UUID, offset uint64) (string, error) {

	sr := io.NewSectionReader(f.r[uuid], 0, 1<<63-1)

	if _, err := sr.Seek(int64(offset), io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to Seek to offset 0x%x: %v", offset, err)
	}

	s, err := bufio.NewReader(sr).ReadString('\x00')
	if err != nil {
		return "", fmt.Errorf("failed to ReadString as offset 0x%x, %v", offset, err)
	}

	if len(s) > 0 {
		return strings.Trim(s, "\x00"), nil
	}

	return "", fmt.Errorf("string not found at offset 0x%x", offset)
}

func (f *File) getExportTrieSymbols(i *CacheImage) ([]trie.TrieEntry, error) {
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

	syms, err := trie.ParseTrie(exportTrie, i.LoadAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get export trie symbols for image %s: %v", filepath.Base(i.Name), err)
	}

	return syms, nil
}

// GetAllExportedSymbols prints out all the exported symbols
func (f *File) GetAllExportedSymbols(dump bool) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	for _, image := range f.Images {
		if !image.Analysis.State.IsExportsDone() {
			syms, err := f.getExportTrieSymbols(image)
			if err != nil {
				if errors.Is(err, ErrNoExportTrieInMachO) {
					m, err := image.GetMacho()
					if err != nil {
						return err
					}

					for _, sym := range m.Symtab.Syms {
						// TODO: Handle ReExports
						if dump {
							fmt.Fprintf(w, "%s\n", sym.String(m))
						} else {
							f.AddressToSymbol[sym.Value] = sym.Name
						}
					}
					w.Flush()

					if binds, err := m.GetBindInfo(); err == nil {
						for _, bind := range binds {
							if dump {
								fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.Offset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
							} else {
								f.AddressToSymbol[bind.Start+bind.Offset] = bind.Name
							}
						}
						w.Flush()
					}
					image.Analysis.State.SetExports(true)
				} else {
					return err
				}
			} else {
				m, err := image.GetMacho()
				if err != nil {
					return err
				}

				for _, sym := range syms {
					if sym.Flags.ReExport() {
						sym.FoundInDylib = m.LibraryOrdinalName(int(sym.Other - 1))
					} else {
						sym.FoundInDylib = image.Name
					}

					if dump {
						fmt.Fprintf(w, "%s\n", sym)
						// fmt.Println(sym)
					} else {
						f.AddressToSymbol[sym.Address] = sym.Name
					}
				}
				for _, sym := range m.Symtab.Syms {
					f.AddressToSymbol[sym.Value] = sym.Name
				}
				if binds, err := m.GetBindInfo(); err == nil {
					for _, bind := range binds {
						f.AddressToSymbol[bind.Start+bind.Offset] = bind.Name
					}
				}
				image.Analysis.State.SetExports(true)
				w.Flush()
			}
		}
	}

	return nil
}

// GetAllExportedSymbolsForImage prints out all the exported symbols for a given image
func (f *File) GetAllExportedSymbolsForImage(image *CacheImage, dump bool) error {
	if !image.Analysis.State.IsExportsDone() {
		syms, err := f.getExportTrieSymbols(image)
		if err != nil {
			if errors.Is(err, ErrNoExportTrieInMachO) {
				m, err := image.GetMacho()
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
				for _, sym := range m.Symtab.Syms {
					// TODO: Handle ReExports
					if dump {
						var sec string
						if sym.Sect > 0 && int(sym.Sect) <= len(m.Sections) {
							sec = fmt.Sprintf("%s.%s", m.Sections[sym.Sect-1].Seg, m.Sections[sym.Sect-1].Name)
						}
						fmt.Fprintf(w, "%#09x:\t(%s)\t%s\n", sym.Value, sym.Type.String(sec), sym.Name)
					} else {
						f.AddressToSymbol[sym.Value] = sym.Name
					}
				}
				w.Flush()
				// LC_DYLD_INFO binds
				if binds, err := m.GetBindInfo(); err == nil {
					for _, bind := range binds {
						if dump {
							fmt.Fprintf(w, "%#09x:\t(%s.%s|from %s)\t%s\n", bind.Start+bind.Offset, bind.Segment, bind.Section, bind.Dylib, bind.Name)
						} else {
							f.AddressToSymbol[bind.Start+bind.Offset] = bind.Name
						}
					}
					w.Flush()
				}
			} else {
				return err
			}
		} else {
			m, err := image.GetPartialMacho()
			if err != nil {
				return err
			}

			for _, sym := range syms {
				if sym.Flags.ReExport() {
					sym.FoundInDylib = m.ImportedLibraries()[sym.Other-1]
				}

				if dump {
					fmt.Println(sym)
				} else {
					f.AddressToSymbol[sym.Address] = sym.Name
				}
			}
		}

		image.Analysis.State.SetExports(true)
	}

	return nil
}

// OpenOrCreateA2SCache returns an address to symbol map if the cache file exists
// otherwise it will create a NEW one
func (f *File) OpenOrCreateA2SCache(cacheFile string) error {
	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		log.Info("parsing public symbols...")
		err = f.GetAllExportedSymbols(false)
		if err != nil {
			// return err
			log.Errorf("failed to parse all exported symbols: %v", err)
		}

		log.Info("parsing private symbols...")
		err = f.ParseLocalSyms()
		if errors.Is(err, ErrNoLocals) {
			utils.Indent(log.Warn, 2)("cache does NOT contain local symbols")
		} else if err != nil {
			return err
		}

		log.Info("parsing objc symbols...")
		if err := f.ParseAllObjc(); err != nil {
			return err
		}

		if err := f.SaveAddrToSymMap(cacheFile); err != nil {
			return err
		}

		return nil
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

func (f *File) FindExportedSymbol(symbolName string) (*trie.TrieEntry, error) {

	for _, image := range f.Images {
		if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
			log.Debugf("Scanning Image: %s", image.Name)
			syms, err := f.getExportTrieSymbols(image)
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

func (f *File) FindExportedSymbolInImage(imagePath, symbolName string) (*trie.TrieEntry, error) {

	image, err := f.Image(imagePath)
	if err != nil {
		return nil, err
	}

	syms, err := f.getExportTrieSymbols(image)
	if err != nil {
		return nil, err
	}

	for _, sym := range syms {
		if sym.Name == symbolName {
			return &sym, nil
		}
	}

	return nil, fmt.Errorf("failed to find in image %s export trie: %w", imagePath, ErrSymbolNotInExportTrie)
}

// GetSymbolAddress returns the virtual address and possibly the dylib containing a given symbol
func (f *File) GetSymbolAddress(symbol, imageName string) (uint64, *CacheImage, error) {
	if len(imageName) > 0 {
		if sym, _ := f.FindExportedSymbolInImage(imageName, symbol); sym != nil {
			if image, err := f.Image(imageName); err != nil {
				return sym.Address, image, err
			} else {
				return sym.Address, image, nil
			}
		}
	} else {
		// // Search ALL dylibs for the symbol
		// for _, image := range f.Images {
		// 	if sym, _ := f.FindExportedSymbolInImage(image.Name, symbol); sym != nil {
		// 		return sym.Address, image, nil
		// 	}
		// }

		// Search addr2sym map
		for addr, sym := range f.AddressToSymbol {
			if strings.EqualFold(sym, symbol) {
				image, err := f.GetImageContainingVMAddr(addr)
				if err != nil {
					return 0, nil, fmt.Errorf("found symbol in local symbols, but address not in cache: %v", err)
				}
				return addr, image, nil
			}
		}
	}

	return 0, nil, fmt.Errorf("failed to find symbol %s", symbol)
}

// GetExportedSymbolAddress returns the address of an images exported symbol
// func (f *File) GetExportedSymbolAddress(symbol string) (*CacheExportedSymbol, error) {
// 	for _, image := range f.Images {
// 		if exportSym, err := f.findSymbolInExportTrieForImage(symbol, image); err == nil {
// 			return exportSym, nil
// 		}
// 	}
// 	return nil, fmt.Errorf("symbol was not found in ExportsTrie")
// }

// GetExportedSymbolAddressInImage returns the address of an given image's exported symbol
// func (f *File) GetExportedSymbolAddressInImage(imagePath, symbol string) (*CacheExportedSymbol, error) {
// 	return f.findSymbolInExportTrieForImage(symbol, f.Image(imagePath))
// }

// func (f *File) findSymbolInExportTrieForImage(symbol string, image *CacheImage) (*CacheExportedSymbol, error) {

// 	var reExportSymBytes []byte

// 	exportedSymbol := &CacheExportedSymbol{
// 		FoundInDylib: image.Name,
// 		Name:         symbol,
// 	}

// 	exportTrie, err := f.getExportTrieData(image)
// 	if err != nil {
// 		return nil, err
// 	}

// 	symbolNode, err := trie.WalkTrie(exportTrie, symbol)
// 	if err != nil {
// 		return nil, fmt.Errorf("symbol was not found in ExportsTrie")
// 	}

// 	r := bytes.NewReader(exportTrie)

// 	r.Seek(int64(symbolNode), io.SeekStart)

// 	symFlagInt, err := trie.ReadUleb128(r)
// 	if err != nil {
// 		return nil, err
// 	}

// 	exportedSymbol.Flags = CacheExportFlag(symFlagInt)

// 	if exportedSymbol.Flags.ReExport() {
// 		symOrdinalInt, err := trie.ReadUleb128(r)
// 		if err != nil {
// 			return nil, err
// 		}
// 		log.Debugf("ReExport symOrdinal: %d", symOrdinalInt)
// 		for {
// 			s, err := r.ReadByte()
// 			if err == io.EOF {
// 				break
// 			}
// 			if s == '\x00' {
// 				break
// 			}
// 			reExportSymBytes = append(reExportSymBytes, s)
// 		}
// 	}

// 	symValueInt, err := trie.ReadUleb128(r)
// 	if err != nil {
// 		return nil, err
// 	}
// 	exportedSymbol.Value = symValueInt

// 	if exportedSymbol.Flags.StubAndResolver() {
// 		symOtherInt, err := trie.ReadUleb128(r)
// 		if err != nil {
// 			return nil, err
// 		}
// 		// TODO: handle stubs
// 		log.Debugf("StubAndResolver: %d", symOtherInt)
// 	}

// 	if exportedSymbol.Flags.Absolute() {
// 		exportedSymbol.Address = symValueInt
// 	} else {
// 		exportedSymbol.Address = symValueInt + image.CacheImageTextInfo.LoadAddress
// 	}

// 	if len(reExportSymBytes) > 0 {
// 		exportedSymbol.Name = fmt.Sprintf("%s (%s)", exportedSymbol.Name, string(reExportSymBytes))
// 	}

// 	return exportedSymbol, nil
// }
