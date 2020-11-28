package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/apex/log"
	"github.com/blacktop/go-macho/types"
	"github.com/pkg/errors"
)

// ParseLocalSyms parses dyld's private symbols
func (f *File) ParseLocalSyms() error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	stringPool := io.NewSectionReader(f.r, int64(f.LocalSymInfo.StringsFileOffset), int64(f.LocalSymInfo.StringsSize))
	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
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
				Name:    strings.Trim(s, "\x00"),
				Nlist64: nlist,
			})
		}
	}

	return nil
}

func (f *File) GetLocalSymbolsForImage(imagePath string) error {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	image := f.Image(imagePath)
	if image == nil {
		return fmt.Errorf("image not found: %s", imagePath)
	}

	sr.Seek(int64(f.LocalSymbolsOffset), os.SEEK_SET)

	if err := binary.Read(sr, f.ByteOrder, &f.LocalSymInfo.CacheLocalSymbolsInfo); err != nil {
		return err
	}

	if f.Is64bit() {
		f.LocalSymInfo.NListByteSize = f.LocalSymInfo.NlistCount * 16
	} else {
		f.LocalSymInfo.NListByteSize = f.LocalSymInfo.NlistCount * 12
	}
	f.LocalSymInfo.NListFileOffset = uint32(f.LocalSymbolsOffset) + f.LocalSymInfo.NlistOffset
	f.LocalSymInfo.StringsFileOffset = uint32(f.LocalSymbolsOffset) + f.LocalSymInfo.StringsOffset

	sr.Seek(int64(uint32(f.LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), os.SEEK_SET)

	for i := 0; i < int(f.LocalSymInfo.EntriesCount); i++ {
		if err := binary.Read(sr, f.ByteOrder, &f.Images[i].CacheLocalSymbolsEntry); err != nil {
			return err
		}
	}

	stringPool := io.NewSectionReader(sr, int64(f.LocalSymInfo.StringsFileOffset), int64(f.LocalSymInfo.StringsSize))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)

	for idx := 0; idx < int(f.LocalSymInfo.EntriesCount); idx++ {
		// skip over other images
		if uint32(idx) != image.Index {
			sr.Seek(int64(int(f.Images[idx].NlistCount)*binary.Size(types.Nlist64{})), os.SEEK_CUR)
			continue
		}
		for e := 0; e < int(f.Images[idx].NlistCount); e++ {

			nlist := types.Nlist64{}
			if err := binary.Read(sr, f.ByteOrder, &nlist); err != nil {
				return err
			}

			stringPool.Seek(int64(nlist.Name), os.SEEK_SET)
			s, err := bufio.NewReader(stringPool).ReadString('\x00')
			if err != nil {
				log.Error(errors.Wrapf(err, "failed to read string at: %d", f.LocalSymInfo.StringsFileOffset+nlist.Name).Error())
			}
			f.Images[idx].LocalSymbols = append(f.Images[idx].LocalSymbols, &CacheLocalSymbol64{
				Name:    strings.Trim(s, "\x00"),
				Nlist64: nlist,
			})
		}
		return nil
	}

	return nil
}

func (f *File) FindLocalSymbol(symbol string) (*CacheLocalSymbol64, error) {
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return nil, fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	sr.Seek(int64(uint32(f.LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), os.SEEK_SET)
	stringPool := make([]byte, f.LocalSymInfo.StringsSize)
	sr.ReadAt(stringPool, int64(f.LocalSymInfo.StringsFileOffset))
	nlistName := bytes.Index(stringPool, []byte(symbol))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)
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
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if f.LocalSymbolsOffset == 0 {
		return nil, fmt.Errorf("dyld shared cache does not contain local symbols info")
	}

	image := f.Image(imageName)

	sr.Seek(int64(uint32(f.LocalSymbolsOffset)+f.LocalSymInfo.EntriesOffset), os.SEEK_SET)

	stringPool := make([]byte, f.LocalSymInfo.StringsSize)
	sr.ReadAt(stringPool, int64(f.LocalSymInfo.StringsFileOffset))

	nlistName := bytes.Index(stringPool, []byte(symbol))

	sr.Seek(int64(f.LocalSymInfo.NListFileOffset), os.SEEK_SET)

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
	image := f.Image(imageName)
	for _, sym := range image.LocalSymbols {
		if sym.Name == symbolName {
			return sym
		}
	}
	return nil
}

func (f *File) GetCString(strVMAdr uint64) (string, error) {

	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	strOffset, err := f.GetOffset(strVMAdr)
	if err != nil {
		return "", err
	}

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

func (f *File) getExportTrieData(i *CacheImage) ([]byte, error) {
	var eTrieAddr, eTrieSize uint64
	sr := io.NewSectionReader(f.r, 0, 1<<63-1)

	if i.CacheImageInfoExtra.ExportsTrieAddr == 0 {
		m, err := i.GetPartialMacho()
		if err != nil {
			return nil, err
		}
		if m.DyldExportsTrie() != nil {
			eTrieAddr, _ = f.GetVMAddress(uint64(m.DyldExportsTrie().Offset))
			eTrieSize = uint64(m.DyldExportsTrie().Size)
		} else if m.DyldInfo() != nil {
			eTrieAddr, _ = f.GetVMAddress(uint64(m.DyldInfo().ExportOff))
			eTrieSize = uint64(m.DyldInfo().ExportSize)
		}
	} else {
		eTrieAddr = i.CacheImageInfoExtra.ExportsTrieAddr
		eTrieSize = uint64(i.CacheImageInfoExtra.ExportsTrieSize)
	}

	for _, mapping := range f.Mappings {
		if mapping.Address <= eTrieAddr && (eTrieAddr+eTrieSize) < mapping.Address+mapping.Size {
			sr.Seek(int64(eTrieAddr-mapping.Address+mapping.FileOffset), os.SEEK_SET)
			exportTrie := make([]byte, eTrieSize)
			if err := binary.Read(sr, f.ByteOrder, &exportTrie); err != nil {
				return nil, err
			}
			return exportTrie, nil
		}
	}

	return nil, fmt.Errorf("failed to find export trie for image %s", i.Name)
}

// GetAllExportedSymbols prints out all the exported symbols
func (f *File) GetAllExportedSymbols(dump bool) error {

	for _, image := range f.Images {
		// if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
		exportTrie, err := f.getExportTrieData(image)
		if err != nil {
			return err
		}
		if len(exportTrie) == 0 {
			continue
		}
		syms, err := parseTrie(exportTrie, image.CacheImageTextInfo.LoadAddress)
		if err != nil {
			return err
		}
		if dump {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.DiscardEmptyColumns)
			for _, sym := range syms {
				fmt.Fprintf(w, "0x%8x:\t[%s]\t%s\t%s\n", sym.Address, sym.Flags, sym.Name, image.Name)
			}
			w.Flush()
		} else {
			for _, sym := range syms {
				f.AddressToSymbol[sym.Address] = sym.Name
			}
		}
		// }
	}

	return nil
}

// SaveAddrToSymMap saves the dyld address-to-symbol map to disk
func (f *File) SaveAddrToSymMap(dest string) error {
	buff := new(bytes.Buffer)

	e := gob.NewEncoder(buff)

	// Encoding the map
	err := e.Encode(f.AddressToSymbol)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dest, buff.Bytes(), 0644)
	if err != nil {
		return err
	}

	return nil
}

func (f *File) FindExportedSymbol(symbolName string) (*trieEntry, error) {

	for _, image := range f.Images {
		if image.CacheImageInfoExtra.ExportsTrieSize > 0 {
			log.Debugf("Scanning Image: %s", image.Name)
			exportTrie, err := f.getExportTrieData(image)
			if err != nil {
				return nil, err
			}
			syms, err := parseTrie(exportTrie, image.CacheImageTextInfo.LoadAddress)
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

func (f *File) FindExportedSymbolInImage(imagePath, symbolName string) (*trieEntry, error) {

	image := f.Image(imagePath)
	exportTrie, err := f.getExportTrieData(image)
	if err != nil {
		return nil, err
	}
	syms, err := parseTrie(exportTrie, image.CacheImageTextInfo.LoadAddress)
	if err != nil {
		return nil, err
	}
	for _, sym := range syms {
		if sym.Name == symbolName {
			return &sym, nil
		}
		// fmt.Println(sym.Name)
	}

	return nil, fmt.Errorf("symbol was not found in exports")
}

// GetExportedSymbolAddress returns the address of an images exported symbol
func (f *File) GetExportedSymbolAddress(symbol string) (*CacheExportedSymbol, error) {
	for _, image := range f.Images {
		if exportSym, err := f.findSymbolInExportTrieForImage(symbol, image); err == nil {
			return exportSym, nil
		}
	}
	return nil, fmt.Errorf("symbol was not found in ExportsTrie")
}

// GetExportedSymbolAddressInImage returns the address of an given image's exported symbol
func (f *File) GetExportedSymbolAddressInImage(imagePath, symbol string) (*CacheExportedSymbol, error) {
	return f.findSymbolInExportTrieForImage(symbol, f.Image(imagePath))
}

func (f *File) findSymbolInExportTrieForImage(symbol string, image *CacheImage) (*CacheExportedSymbol, error) {

	var reExportSymBytes []byte

	exportedSymbol := &CacheExportedSymbol{
		FoundInDylib: image.Name,
		Name:         symbol,
	}

	exportTrie, err := f.getExportTrieData(image)
	if err != nil {
		return nil, err
	}

	symbolNode, err := walkTrie(exportTrie, symbol)
	if err != nil {
		return nil, fmt.Errorf("symbol was not found in ExportsTrie")
	}

	r := bytes.NewReader(exportTrie)

	r.Seek(int64(symbolNode), io.SeekStart)

	symFlagInt, err := readUleb128(r)
	if err != nil {
		return nil, err
	}

	exportedSymbol.Flags = CacheExportFlag(symFlagInt)

	if exportedSymbol.Flags.ReExport() {
		symOrdinalInt, err := readUleb128(r)
		if err != nil {
			return nil, err
		}
		log.Debugf("ReExport symOrdinal: %d", symOrdinalInt)
		for {
			s, err := r.ReadByte()
			if err == io.EOF {
				break
			}
			if s == '\x00' {
				break
			}
			reExportSymBytes = append(reExportSymBytes, s)
		}
	}

	symValueInt, err := readUleb128(r)
	if err != nil {
		return nil, err
	}
	exportedSymbol.Value = symValueInt

	if exportedSymbol.Flags.StubAndResolver() {
		symOtherInt, err := readUleb128(r)
		if err != nil {
			return nil, err
		}
		// TODO: handle stubs
		log.Debugf("StubAndResolver: %d", symOtherInt)
	}

	if exportedSymbol.Flags.Absolute() {
		exportedSymbol.Address = symValueInt
	} else {
		exportedSymbol.Address = symValueInt + image.CacheImageTextInfo.LoadAddress
	}

	if len(reExportSymBytes) > 0 {
		exportedSymbol.Name = fmt.Sprintf("%s (%s)", exportedSymbol.Name, string(reExportSymBytes))
	}

	return exportedSymbol, nil
}
