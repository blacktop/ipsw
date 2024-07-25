package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unsafe"

	"github.com/blacktop/go-macho/pkg/trie"
	"github.com/blacktop/go-macho/types"
)

func (f *File) SupportsPrebuiltLoaderSet() bool {
	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].ProgramTrieSize)) {
		return false
	}
	if f.Headers[f.UUID].ProgramTrieAddr == 0 {
		return false
	}
	return true
}

func (f *File) ForEachLaunchLoaderSet(handler func(execPath string, pset *PrebuiltLoaderSet)) error {
	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].ProgramTrieSize)) {
		return ErrPrebuiltLoaderSetNotSupported
	}
	if f.Headers[f.UUID].ProgramTrieAddr == 0 {
		return ErrPrebuiltLoaderSetNotSupported
	}

	uuid, off, err := f.GetOffset(f.Headers[f.UUID].ProgramTrieAddr)
	if err != nil {
		return err
	}

	dat, err := f.ReadBytesForUUID(uuid, int64(off), uint64(f.Headers[f.UUID].ProgramTrieSize))
	if err != nil {
		return err
	}

	r := bytes.NewReader(dat)

	nodes, err := trie.ParseTrie(r)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		r.Seek(int64(node.Offset), io.SeekStart)

		pblsOff, err := trie.ReadUleb128(r)
		if err != nil {
			return err
		}

		uuid, psetOffset, err := f.GetOffset(f.Headers[f.UUID].ProgramsPblSetPoolAddr + uint64(pblsOff))
		if err != nil {
			return err
		}

		pset, err := f.parsePrebuiltLoaderSet(io.NewSectionReader(f.r[uuid], int64(psetOffset), 1<<63-1))
		if err != nil {
			return err
		}

		handler(string(node.Data), pset)
	}

	return nil
}

func (f *File) ForEachLaunchLoaderSetPath(handler func(execPath string)) error {
	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].ProgramTrieSize)) {
		return ErrPrebuiltLoaderSetNotSupported
	}
	if f.Headers[f.UUID].ProgramTrieAddr == 0 {
		return ErrPrebuiltLoaderSetNotSupported
	}

	uuid, off, err := f.GetOffset(f.Headers[f.UUID].ProgramTrieAddr)
	if err != nil {
		return err
	}

	dat, err := f.ReadBytesForUUID(uuid, int64(off), uint64(f.Headers[f.UUID].ProgramTrieSize))
	if err != nil {
		return err
	}

	r := bytes.NewReader(dat)

	nodes, err := trie.ParseTrie(r)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		handler(string(node.Data))
	}

	return nil
}

// GetLaunchLoaderSet returns the PrebuiltLoaderSet for the given executable app path.
func (f *File) GetLaunchLoaderSet(executablePath string) (*PrebuiltLoaderSet, error) {
	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].ProgramTrieSize)) {
		return nil, ErrPrebuiltLoaderSetNotSupported
	}
	if f.Headers[f.UUID].ProgramTrieAddr == 0 {
		return nil, ErrPrebuiltLoaderSetNotSupported
	}

	var psetOffset uint64

	uuid, off, err := f.GetOffset(f.Headers[f.UUID].ProgramTrieAddr)
	if err != nil {
		return nil, err
	}

	dat, err := f.ReadBytesForUUID(uuid, int64(off), uint64(f.Headers[f.UUID].ProgramTrieSize))
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(dat)

	if _, err = trie.WalkTrie(r, executablePath); err != nil {
		return nil, fmt.Errorf("could not find executable %s in the ProgramTrie: %w", executablePath, err)
	}

	poolOffset, err := trie.ReadUleb128(r)
	if err != nil {
		return nil, err
	}

	uuid, psetOffset, err = f.GetOffset(f.Headers[f.UUID].ProgramsPblSetPoolAddr + uint64(poolOffset))
	if err != nil {
		return nil, err
	}

	return f.parsePrebuiltLoaderSet(io.NewSectionReader(f.r[uuid], int64(psetOffset), 1<<63-1))
}

func (f *File) SupportsDylibPrebuiltLoader() bool {
	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].ProgramTrieSize)) {
		return false
	}
	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].DylibsPblSetAddr)) {
		return false
	}
	// FIXME: REMOVE once I have added iOS 18.x support
	if f.Headers[f.UUID].MappingOffset > uint32(unsafe.Offsetof(f.Headers[f.UUID].TPROMappingOffset)) {
		return false
	}
	if f.Headers[f.UUID].DylibsPblSetAddr == 0 {
		return false
	}
	return true
}

// GetLaunchLoader returns the PrebuiltLoader for the given executable in-cache dylib path.
func (f *File) GetDylibPrebuiltLoader(executablePath string) (*PrebuiltLoader, error) {

	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].ProgramTrieSize)) {
		return nil, ErrPrebuiltLoaderSetNotSupported
	}
	if f.Headers[f.UUID].MappingOffset < uint32(unsafe.Offsetof(f.Headers[f.UUID].DylibsPblSetAddr)) {
		return nil, ErrPrebuiltLoaderSetNotSupported
	}
	// FIXME: REMOVE once I have added iOS 18.x support
	if f.Headers[f.UUID].MappingOffset > uint32(unsafe.Offsetof(f.Headers[f.UUID].TPROMappingOffset)) {
		return nil, ErrPrebuiltLoaderSetNotSupported
	}
	if f.Headers[f.UUID].DylibsPblSetAddr == 0 {
		return nil, ErrPrebuiltLoaderSetNotSupported
	}

	uuid, off, err := f.GetOffset(f.Headers[f.UUID].DylibsPblSetAddr)
	if err != nil {
		return nil, err
	}

	sr := io.NewSectionReader(f.r[uuid], int64(off), 1<<63-1)

	var pset PrebuiltLoaderSet
	if err := binary.Read(sr, binary.LittleEndian, &pset.prebuiltLoaderSetHeader); err != nil {
		return nil, err
	}

	sr.Seek(int64(pset.LoadersArrayOffset), io.SeekStart)

	loaderOffsets := make([]uint32, pset.LoadersArrayCount)
	if err := binary.Read(sr, binary.LittleEndian, &loaderOffsets); err != nil {
		return nil, err
	}

	imgIdx, err := f.HasImagePath(executablePath)
	if err != nil {
		return nil, err
	} else if imgIdx < 0 {
		return nil, fmt.Errorf("image not found")
	}

	sr.Seek(int64(loaderOffsets[imgIdx]), io.SeekStart)

	return f.parsePrebuiltLoader(io.NewSectionReader(f.r[uuid], int64(off)+int64(loaderOffsets[imgIdx]), 1<<63-1))
}

func (f *File) parsePrebuiltLoaderSet(sr *io.SectionReader) (*PrebuiltLoaderSet, error) {
	var pset PrebuiltLoaderSet
	if err := binary.Read(sr, binary.LittleEndian, &pset.prebuiltLoaderSetHeader); err != nil {
		return nil, err
	}

	if pset.Magic != PrebuiltLoaderSetMagic {
		return nil, fmt.Errorf("invalid magic for PrebuiltLoaderSet: expected %x got %x", PrebuiltLoaderSetMagic, pset.Magic)
	}

	sr.Seek(int64(pset.LoadersArrayOffset), io.SeekStart)

	loaderOffsets := make([]uint32, pset.LoadersArrayCount)
	if err := binary.Read(sr, binary.LittleEndian, &loaderOffsets); err != nil {
		return nil, err
	}

	for _, loaderOffset := range loaderOffsets {
		pbl, err := f.parsePrebuiltLoader(io.NewSectionReader(sr, int64(loaderOffset), 1<<63-1))
		if err != nil {
			return nil, err
		}
		pset.Loaders = append(pset.Loaders, *pbl)
	}

	if pset.CachePatchCount > 0 { // FIXME: this is in "/usr/bin/abmlite" but the values don't make sense (dyld_closure_util gets the same values)
		sr.Seek(int64(pset.CachePatchOffset), io.SeekStart)
		pset.Patches = make([]CachePatch, pset.CachePatchCount)
		if err := binary.Read(sr, binary.LittleEndian, &pset.Patches); err != nil {
			return nil, err
		}
	}
	if pset.DyldCacheUuidOffset > 0 {
		sr.Seek(int64(pset.DyldCacheUuidOffset), io.SeekStart)
		var dcUUID types.UUID
		if err := binary.Read(sr, binary.LittleEndian, &dcUUID); err != nil {
			return nil, err
		}
	}
	if pset.MustBeMissingPathsCount > 0 {
		sr.Seek(int64(pset.MustBeMissingPathsOffset), io.SeekStart)
		br := bufio.NewReader(sr)
		for i := 0; i < int(pset.MustBeMissingPathsCount); i++ {
			s, err := br.ReadString('\x00')
			if err != nil {
				return nil, err
			}
			pset.MustBeMissingPaths = append(pset.MustBeMissingPaths, strings.TrimSuffix(s, "\x00"))
		}
	}
	if pset.ObjcSelectorHashTableOffset > 0 {
		sr.Seek(int64(pset.ObjcSelectorHashTableOffset), io.SeekStart)
		var o ObjCSelectorOpt
		if err := binary.Read(sr, f.ByteOrder, &o.objCStringTable); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc selector optimization string table: %v", err)
		}
		tabAddr, _ := sr.Seek(0, io.SeekCurrent)
		o.Tab = make([]byte, o.objCStringTable.Mask+1)
		if err := binary.Read(sr, f.ByteOrder, &o.Tab); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc selector optimization tabs: %v", err)
		}
		o.Checkbytes = make([]byte, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Checkbytes); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc selector optimization checkbytes: %v", err)
		}
		sr.Seek(int64(tabAddr)+int64(o.RoundedTabSize+o.RoundedCheckBytesSize), io.SeekStart)
		o.Offsets = make([]BindTargetRef, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Offsets); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc selector optimization offsets: %v", err)
		}
		pset.SelectorTable = &o
	}
	if pset.ObjcClassHashTableOffset > 0 {
		sr.Seek(int64(pset.ObjcClassHashTableOffset), io.SeekStart)
		var o ObjCClassOpt
		if err := binary.Read(sr, f.ByteOrder, &o.objCStringTable); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc class optimization string table: %v", err)
		}
		tabAddr, _ := sr.Seek(0, io.SeekCurrent)
		o.Tab = make([]byte, o.objCStringTable.Mask+1)
		if err := binary.Read(sr, f.ByteOrder, &o.Tab); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc class optimization tabs: %v", err)
		}
		o.Checkbytes = make([]byte, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Checkbytes); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc class optimization checkbytes: %v", err)
		}
		sr.Seek(int64(tabAddr)+int64(o.RoundedTabSize+o.RoundedCheckBytesSize), io.SeekStart)
		o.Offsets = make([]BindTargetRef, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Offsets); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc class optimization class name offsets: %v", err)
		}
		o.Classes = make([]BindTargetRef, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Classes); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc class optimization class impl offsets: %v", err)
		}
		var dupCount uint64
		if err := binary.Read(sr, f.ByteOrder, &dupCount); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc class optimization duplicate count: %v", err)
		}
		o.Duplicates = make([]BindTargetRef, dupCount)
		if err := binary.Read(sr, f.ByteOrder, &o.Duplicates); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc class optimization duplicate offsets: %v", err)
		}
		pset.ClassTable = &o
	}
	if pset.ObjcProtocolHashTableOffset > 0 {
		sr.Seek(int64(pset.ObjcProtocolHashTableOffset), io.SeekStart)
		var o ObjCClassOpt
		if err := binary.Read(sr, f.ByteOrder, &o.objCStringTable); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc protocol optimization string table: %v", err)
		}
		tabAddr, _ := sr.Seek(0, io.SeekCurrent)
		o.Tab = make([]byte, o.objCStringTable.Mask+1)
		if err := binary.Read(sr, f.ByteOrder, &o.Tab); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc protocol optimization tabs: %v", err)
		}
		o.Checkbytes = make([]byte, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Checkbytes); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc protocol optimization checkbytes: %v", err)
		}
		sr.Seek(int64(tabAddr)+int64(o.RoundedTabSize+o.RoundedCheckBytesSize), io.SeekStart)
		o.Offsets = make([]BindTargetRef, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Offsets); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc protocol optimization protocol name offsets: %v", err)
		}
		o.Classes = make([]BindTargetRef, o.objCStringTable.Capacity)
		if err := binary.Read(sr, f.ByteOrder, &o.Classes); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc protocol optimization protocol impl offsets: %v", err)
		}
		var dupCount uint64
		if err := binary.Read(sr, f.ByteOrder, &dupCount); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc protocol optimization duplicate count: %v", err)
		}
		o.Duplicates = make([]BindTargetRef, dupCount)
		if err := binary.Read(sr, f.ByteOrder, &o.Duplicates); err != nil {
			return nil, fmt.Errorf("failed to read prebuilt objc protocol optimization duplicate offsets: %v", err)
		}
		pset.ProtocolTable = &o
	}
	if !pset.HasOptimizedObjC() && pset.ObjcProtocolClassCacheOffset > 0 { // FIXME: this is a hack (would have panic'ed while parsing macOS 12.6.1 DSC prebuilt for /bin/ls) possibly uninitialized data
		return &pset, nil
	}
	if pset.HasOptimizedSwift() {
		if pset.SwiftTypeConformanceTableOffset > 0 {
			sr.Seek(int64(pset.SwiftTypeConformanceTableOffset), io.SeekStart)
			var mmap SwiftConformanceMultiMap
			if err := binary.Read(sr, f.ByteOrder, &mmap); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift type conformance map: %v", err)
			}
			var hashBufferCount uint64
			if err := binary.Read(sr, f.ByteOrder, &hashBufferCount); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift type conformance hashBufferCount: %v", err)
			}
			hashBuffer := make([]uint64, hashBufferCount)
			if err := binary.Read(sr, f.ByteOrder, &hashBuffer); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift type conformance hashBuffer: %v", err)
			}
			var nodeBufferCount uint64
			if err := binary.Read(sr, f.ByteOrder, &nodeBufferCount); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift type conformance nodeBufferCount: %v", err)
			}
			pset.SwiftTypeProtocolTable = make([]SwiftTypeProtocolNodeEntryT, nodeBufferCount)
			if err := binary.Read(sr, f.ByteOrder, &pset.SwiftTypeProtocolTable); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift type conformance nodeBuffer: %v", err)
			}
		}
		if pset.SwiftMetadataConformanceTableOffset > 0 {
			sr.Seek(int64(pset.SwiftMetadataConformanceTableOffset), io.SeekStart)
			var mmap SwiftConformanceMultiMap
			if err := binary.Read(sr, f.ByteOrder, &mmap); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift metadata conformance map: %v", err)
			}
			var hashBufferCount uint64
			if err := binary.Read(sr, f.ByteOrder, &hashBufferCount); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift metadata conformance hashBufferCount: %v", err)
			}
			hashBuffer := make([]uint64, hashBufferCount)
			if err := binary.Read(sr, f.ByteOrder, &hashBuffer); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift metadata conformance hashBuffer: %v", err)
			}
			var nodeBufferCount uint64
			if err := binary.Read(sr, f.ByteOrder, &nodeBufferCount); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift metadata conformance nodeBufferCount: %v", err)
			}
			pset.SwiftMetadataProtocolTable = make([]SwiftMetadataConformanceNodeEntryT, nodeBufferCount)
			if err := binary.Read(sr, f.ByteOrder, &pset.SwiftMetadataProtocolTable); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift metadata conformance nodeBuffer: %v", err)
			}
		}
		if pset.SwiftForeignTypeConformanceTableOffset > 0 {
			sr.Seek(int64(pset.SwiftForeignTypeConformanceTableOffset), io.SeekStart)
			var mmap SwiftConformanceMultiMap
			if err := binary.Read(sr, f.ByteOrder, &mmap); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift foreign type conformance map: %v", err)
			}
			var hashBufferCount uint64
			if err := binary.Read(sr, f.ByteOrder, &hashBufferCount); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift foreign type  conformance hashBufferCount: %v", err)
			}
			hashBuffer := make([]uint64, hashBufferCount)
			if err := binary.Read(sr, f.ByteOrder, &hashBuffer); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift foreign type  conformance hashBuffer: %v", err)
			}
			var nodeBufferCount uint64
			if err := binary.Read(sr, f.ByteOrder, &nodeBufferCount); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift foreign type  conformance nodeBufferCount: %v", err)
			}
			pset.SwiftForeignTypeProtocolTable = make([]SwiftForeignTypeConformanceNodeEntryT, nodeBufferCount)
			if err := binary.Read(sr, f.ByteOrder, &pset.SwiftForeignTypeProtocolTable); err != nil {
				return nil, fmt.Errorf("failed to read prebuilt swift foreign type  conformance nodeBuffer: %v", err)
			}
		}
	}

	return &pset, nil
}

// parsePrebuiltLoader parses a prebuilt loader from a section reader.
func (f *File) parsePrebuiltLoader(sr *io.SectionReader) (*PrebuiltLoader, error) {
	var pbl PrebuiltLoader
	if err := binary.Read(sr, binary.LittleEndian, &pbl.prebuiltLoaderHeader); err != nil {
		return nil, err
	}

	if pbl.Magic != LoaderMagic {
		return nil, fmt.Errorf("invalid magic for prebuilt loader: expected %x got %x", LoaderMagic, pbl.Magic)
	}

	if pbl.PathOffset > 0 {
		sr.Seek(int64(pbl.PathOffset), io.SeekStart)
		br := bufio.NewReader(sr)
		path, err := br.ReadString('\x00')
		if err != nil {
			return nil, err
		}
		pbl.Path = strings.TrimSuffix(path, "\x00")
	}
	if pbl.AltPathOffset > 0 {
		sr.Seek(int64(pbl.AltPathOffset), io.SeekStart)
		br := bufio.NewReader(sr)
		path, err := br.ReadString('\x00')
		if err != nil {
			return nil, err
		}
		pbl.AltPath = strings.TrimSuffix(path, "\x00")
	}
	if pbl.FileValidationOffset > 0 {
		sr.Seek(int64(pbl.FileValidationOffset), io.SeekStart)
		var fv fileValidation
		if err := binary.Read(sr, binary.LittleEndian, &fv); err != nil {
			return nil, err
		}
		pbl.FileValidation = &fv
	}
	if pbl.RegionsCount() > 0 {
		sr.Seek(int64(pbl.RegionsOffset), io.SeekStart)
		pbl.Regions = make([]Region, pbl.RegionsCount())
		if err := binary.Read(sr, binary.LittleEndian, &pbl.Regions); err != nil {
			return nil, err
		}
	}
	if pbl.DependentLoaderRefsArrayOffset > 0 {
		sr.Seek(int64(pbl.DependentLoaderRefsArrayOffset), io.SeekStart)
		depsArray := make([]LoaderRef, pbl.DepCount)
		if err := binary.Read(sr, binary.LittleEndian, &depsArray); err != nil {
			return nil, err
		}
		kindsArray := make([]DependentKind, pbl.DepCount)
		if pbl.DependentKindArrayOffset > 0 {
			sr.Seek(int64(pbl.DependentKindArrayOffset), io.SeekStart)
			if err := binary.Read(sr, binary.LittleEndian, &kindsArray); err != nil {
				return nil, err
			}
		}
		for idx, dep := range depsArray {
			img := dep.String()
			if dep.Index() < uint16(len(f.Images)) {
				img = f.Images[dep.Index()].Name
			}
			pbl.Dependents = append(pbl.Dependents, dependent{
				Name: img,
				Kind: kindsArray[idx],
			})
		}
	}
	if pbl.BindTargetRefsCount > 0 {
		sr.Seek(int64(pbl.BindTargetRefsOffset), io.SeekStart)
		pbl.BindTargets = make([]BindTargetRef, pbl.BindTargetRefsCount)
		if err := binary.Read(sr, binary.LittleEndian, &pbl.BindTargets); err != nil {
			return nil, err
		}
	}
	if pbl.OverrideBindTargetRefsCount > 0 {
		sr.Seek(int64(pbl.OverrideBindTargetRefsOffset), io.SeekStart)
		pbl.OverrideBindTargets = make([]BindTargetRef, pbl.OverrideBindTargetRefsCount)
		if err := binary.Read(sr, binary.LittleEndian, &pbl.OverrideBindTargets); err != nil {
			return nil, err
		}
	}
	if pbl.ObjcBinaryInfoOffset > 0 {
		sr.Seek(int64(pbl.ObjcBinaryInfoOffset), io.SeekStart)
		var ofi ObjCBinaryInfo
		if err := binary.Read(sr, binary.LittleEndian, &ofi); err != nil {
			return nil, err
		}
		pbl.ObjcFixupInfo = &ofi
		sr.Seek(int64(pbl.ObjcBinaryInfoOffset)+int64(pbl.ObjcFixupInfo.ProtocolFixupsOffset), io.SeekStart)
		pbl.ObjcCanonicalProtocolFixups = make([]bool, pbl.ObjcFixupInfo.ProtocolListCount)
		if err := binary.Read(sr, binary.LittleEndian, &pbl.ObjcCanonicalProtocolFixups); err != nil {
			return nil, err
		}
		sr.Seek(int64(pbl.ObjcBinaryInfoOffset)+int64(pbl.ObjcFixupInfo.SelectorReferencesFixupsOffset), io.SeekStart)
		pbl.ObjcSelectorFixups = make([]BindTargetRef, pbl.ObjcFixupInfo.SelectorReferencesFixupsCount)
		if err := binary.Read(sr, binary.LittleEndian, &pbl.ObjcSelectorFixups); err != nil {
			return nil, err
		}
	}
	if pbl.IndexOfTwin != NoUnzipperedTwin {
		pbl.Twin = f.Images[pbl.IndexOfTwin].Name
	}
	if pbl.PatchTableOffset > 0 {
		sr.Seek(int64(pbl.PatchTableOffset), io.SeekStart)
		for {
			var patch DylibPatch
			if err := binary.Read(sr, binary.LittleEndian, &patch); err != nil {
				return nil, err
			}
			pbl.DylibPatches = append(pbl.DylibPatches, patch)
			if patch.Kind == endOfPatchTable {
				break
			}
		}
	}

	return &pbl, nil
}
