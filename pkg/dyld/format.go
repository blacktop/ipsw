package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/blacktop/go-macho/types"
	"github.com/dustin/go-humanize"
	"github.com/olekukonko/tablewriter"
)

func (dch CacheHeader) String() string {
	var magicBytes []byte = dch.Magic[:]

	return fmt.Sprintf(
		"Magic               = %s\n"+
			"MappingOffset       = %08X\n"+
			"MappingCount        = %d\n"+
			"ImagesOffset        = %08X\n"+
			"ImagesCount         = %d\n"+
			"DyldBaseAddress     = %08X\n"+
			"CodeSignatureOffset = %08X\n"+
			"CodeSignatureSize   = %08X\n"+
			"SlideInfoOffset     = %08X\n"+
			"SlideInfoSize       = %08X\n"+
			"LocalSymbolsOffset  = %08X\n"+
			"LocalSymbolsSize    = %08X\n"+
			"UUID                = %s\n"+
			"Platform            = %s\n"+
			"Format              = %d\n",
		bytes.Trim(magicBytes, "\x00"),
		dch.MappingOffset,
		dch.MappingCount,
		dch.ImagesOffsetOld,
		dch.ImagesCountOld,
		dch.DyldBaseAddress,
		dch.CodeSignatureOffset,
		dch.CodeSignatureSize,
		dch.SlideInfoOffsetUnused,
		dch.SlideInfoSizeUnused,
		dch.LocalSymbolsOffset,
		dch.LocalSymbolsSize,
		dch.UUID.String(),
		dch.Platform.String(),
		dch.FormatVersion.Version(),
	)
}

func (m *CacheMapping) String() string {
	return fmt.Sprintf(
		"Name       = %s\n"+
			"Address    = %#x\n"+
			"Size       = %s\n"+
			"FileOffset = %#x\n"+
			"MaxProt    = %s\n"+
			"InitProt   = %s\n",
		m.Name,
		m.Address,
		humanize.Bytes(m.Size),
		m.FileOffset,
		m.MaxProt.String(),
		m.InitProt.String(),
	)
}

func (c CacheImageInfo) String() string {
	return fmt.Sprintf(
		"Address        = %016X\n"+
			"ModTime        = %016X\n"+
			"Inode          = %d\n"+
			"PathFileOffset = %08X\n",
		c.Address,
		c.ModTime,
		c.Inode,
		c.PathFileOffset,
	)
}

func (dch CacheHeader) Print() {
	fmt.Println("Header")
	fmt.Println("======")
	fmt.Println(dch.String())
	fmt.Printf("Slide Info:     %4dKB,  file offset: 0x%09X -> 0x%09X\n", dch.SlideInfoSizeUnused/1024, dch.SlideInfoOffsetUnused, dch.SlideInfoOffsetUnused+dch.SlideInfoSizeUnused)
	fmt.Printf("Local Symbols:  %3dMB,  file offset: 0x%09X -> 0x%09X\n", dch.LocalSymbolsSize/(1024*1024), dch.LocalSymbolsOffset, dch.LocalSymbolsOffset+dch.LocalSymbolsSize)
	fmt.Printf("Accelerate Tab: %3dKB,  address: 0x%09X -> 0x%09X\n", dch.AccelerateInfoSizeUnusedOrDyldStartFuncAddr/1024, dch.AccelerateInfoAddrUnusedOrDyldAddr, dch.AccelerateInfoAddrUnusedOrDyldAddr+dch.AccelerateInfoSizeUnusedOrDyldStartFuncAddr)
	fmt.Println()
}

func (l *localSymbolInfo) Print() {
	fmt.Printf("Local symbols nlist array:  %3dMB,  file offset: 0x%09X -> 0x%09X\n", l.NListByteSize/(1024*1024), l.NListFileOffset, l.NListFileOffset+l.NListByteSize)
	fmt.Printf("Local symbols string pool:  %3dMB,  file offset: 0x%09X -> 0x%09X\n", l.StringsSize/(1024*1024), l.StringsFileOffset, l.StringsFileOffset+l.StringsSize)
}

func (mappings cacheMappings) String() string {
	tableString := &strings.Builder{}

	mdata := [][]string{}
	for _, mapping := range mappings {
		mdata = append(mdata, []string{
			mapping.Name,
			mapping.InitProt.String(),
			mapping.MaxProt.String(),
			fmt.Sprintf("%d MB", mapping.Size/(1024*1024)),
			// humanize.Bytes(mapping.Size),
			fmt.Sprintf("%08X -> %08X", mapping.Address, mapping.Address+mapping.Size),
			fmt.Sprintf("%08X -> %08X", mapping.FileOffset, mapping.FileOffset+mapping.Size),
		})
	}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Seg", "InitProt", "MaxProt", "Size", "Address", "File Offset"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(mdata)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()

	return tableString.String()
}

func (mapping CacheMappingWithSlideInfo) String() string {
	tableString := &strings.Builder{}

	mdata := [][]string{}

	slideInfoSize := fmt.Sprintf("%#08x -> %#08x", mapping.SlideInfoOffset, mapping.SlideInfoOffset+mapping.SlideInfoSize)
	if mapping.SlideInfoSize == 0 {
		slideInfoSize = fmt.Sprintf("%#08x", mapping.SlideInfoOffset)
	}

	mdata = append(mdata, []string{
		mapping.Name,
		mapping.InitProt.String(),
		mapping.MaxProt.String(),
		fmt.Sprintf("%#08x (%s)", mapping.Size, humanize.Bytes(mapping.Size)),
		fmt.Sprintf("%#08x", mapping.Address),
		fmt.Sprintf("%#08x", mapping.FileOffset),
		slideInfoSize,
		fmt.Sprintf("%d", mapping.Flags),
	})

	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Seg", "InitProt", "MaxProt", "Size", "Address", "File Offset", "Slide Info Offset", "Flags"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(mdata)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()

	return tableString.String()
}

func (mappings cacheMappingsWithSlideInfo) String(slideVersion uint32, verbose bool) string {
	tableString := &strings.Builder{}

	mdata := [][]string{}
	for _, mapping := range mappings {
		mappingAddr := fmt.Sprintf("%#08x", mapping.Address)
		mappingOff := fmt.Sprintf("%#08x", mapping.FileOffset)
		mappingInitProt := mapping.InitProt.String()
		mappingMaxProt := mapping.MaxProt.String()
		mappingFlags := mapping.Flags.String()
		if verbose {
			mappingAddr = fmt.Sprintf("%#08x -> %#08x", mapping.Address, mapping.Address+mapping.Size)
			mappingOff = fmt.Sprintf("%#08x -> %#08x", mapping.FileOffset, mapping.FileOffset+mapping.Size)
			mappingInitProt += fmt.Sprintf(" (%d)", mapping.InitProt)
			mappingMaxProt += fmt.Sprintf(" (%d)", mapping.MaxProt)
			mappingFlags += fmt.Sprintf(" (%d)", mapping.Flags)
		}
		var slideInfoSize string
		if mapping.SlideInfoSize > 0 {
			slideInfoSize = fmt.Sprintf("%#08x -> %#08x", mapping.SlideInfoOffset, mapping.SlideInfoOffset+mapping.SlideInfoSize)
		}
		mdata = append(mdata, []string{
			mapping.Name,
			mappingInitProt,
			mappingMaxProt,
			fmt.Sprintf("%#08x (%s)", mapping.Size, humanize.Bytes(mapping.Size)),
			mappingAddr,
			mappingOff,
			slideInfoSize,
			mappingFlags,
		})
	}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Seg", "InitProt", "MaxProt", "Size", "Address", "File Offset", fmt.Sprintf("Slide Info (v%d) Offset", slideVersion), "Flags"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(mdata)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render()

	return tableString.String()
}

func (images cacheImages) Print() {
	fmt.Println("Images")
	fmt.Println("======")
	for idx, image := range images {
		fmt.Printf("%d:\t%08x %s\n", idx+1, image.Info.Address, image.Name)
	}
}

func (f *File) String(verbose bool) string {
	var slideVersion uint32

	if f.SlideInfo != nil {
		slideVersion = f.SlideInfo.GetVersion()
	}

	return fmt.Sprintf(
		"Header\n"+
			"======\n"+
			"Magic          = \"%s\"\n"+
			"Platform       = %s\n"+
			"%s"+ // alt platform
			"%s"+ // os version
			"%s"+ // alt os version
			"%s"+ // format
			"%s"+ // max slide
			"%s"+ // image count
			"%s\n"+ // sub cache info
			"%s"+ // shared region
			"%s"+ // local symbols
			"%s"+ // image text info
			"%s"+ // slideInfo
			"%s"+ // branchPools
			"%s"+ // accelerateInfo
			"%s"+ // patch info
			"%s"+ // progClosures
			"%s"+ // progClosuresTrie
			"%s"+ // prebuiltLoaderSet
			"%s"+ // prebuiltLoaderSet pool
			"%s"+ // dynamic config
			"%s"+ // objcOpts
			"%s"+ // swiftOpts
			"%s"+ // dyld/_dyld_start addrs
			"%s", // mappings
		f.Headers[f.UUID].Magic.String(),
		f.Headers[f.UUID].Platform,
		f.getAltPlatform(f.UUID),
		f.getOSVersion(f.UUID),
		f.getAltOSVersion(f.UUID),
		f.getFormatVersion(f.UUID),
		f.getMaxSlide(f.UUID),
		f.getImageCount(f.UUID),
		f.getSubCacheCount(),
		f.getSharedRegion(f.UUID),
		f.getLocalSymbols(),
		f.getImagesTextInfo(f.UUID),
		f.getSlideInfo(f.UUID, slideVersion),
		f.getBranchPools(f.UUID),
		f.getAccelerateInfo(f.UUID),
		f.getPatchInfo(f.UUID),
		f.getProgClosures(f.UUID),
		f.getProgClosuresTrie(f.UUID),
		f.getPrebuiltLoaderSet(f.UUID),
		f.getPrebuiltLoaderSetPool(f.UUID),
		f.getDynamicConfig(f.UUID),
		f.getObjcOpts(f.UUID),
		f.getSwiftOpts(f.UUID),
		f.getDyldInfo(f.UUID),
		f.getMappings(slideVersion, verbose),
	)
}

func (f *File) getFormatVersion(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].FormatVersion > 0 {
		output = fmt.Sprintf("Format         = %s\n", f.Headers[uuid].FormatVersion.String())
	}
	return output
}

func (f *File) getOSVersion(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].OsVersion > 0 {
		output = fmt.Sprintf("OS Version     = %s\n", f.Headers[uuid].OsVersion.String())
	}
	return output
}
func (f *File) getAltOSVersion(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].AltOsVersion > 0 {
		output = fmt.Sprintf("Alt OS Version = %s\n", f.Headers[uuid].AltOsVersion.String())
	}
	return output
}
func (f *File) getAltPlatform(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].AltPlatform > 0 {
		output = fmt.Sprintf("Alt Platform   = %s\n", f.Headers[uuid].AltPlatform.String())
	}
	return output
}

func (f *File) getMaxSlide(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].MaxSlide > 0 {
		output = fmt.Sprintf("Max Slide      = %s\n", f.Headers[uuid].MaxSlide)
	}
	return output
}

func (f *File) getImageCount(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].ImagesCountOld > 0 {
		output = fmt.Sprintf("Num Images     = %d\n", f.Headers[uuid].ImagesCountOld)
	} else {
		output = fmt.Sprintf("Num Images     = %d\n", f.Headers[uuid].ImagesCount)
	}
	return output
}

func (f *File) getSubCacheCount() string {
	var output string
	if f.IsDyld4 {
		output = fmt.Sprintf("Num SubCaches  = %d\n", f.Headers[f.UUID].SubCacheArrayCount)
	}
	return output
}

func (f *File) getLocalSymbols() string {
	var output string
	if f.LocalSymInfo.NListFileOffset > 0 && f.LocalSymInfo.StringsFileOffset > 0 {
		output = fmt.Sprintf(
			"Local Symbols (nlist array): %3dMB, offset:  0x%09X -> 0x%09X\n"+
				"Local Symbols (string pool): %3dMB, offset:  0x%09X -> 0x%09X\n",
			f.LocalSymInfo.NListByteSize/(1024*1024),
			f.LocalSymInfo.NListFileOffset,
			f.LocalSymInfo.NListFileOffset+f.LocalSymInfo.NListByteSize,
			f.LocalSymInfo.StringsSize/(1024*1024),
			f.LocalSymInfo.StringsFileOffset,
			f.LocalSymInfo.StringsFileOffset+f.LocalSymInfo.StringsSize,
		)
	}
	return output
}

func (f *File) getImagesTextInfo(uuid types.UUID) string {
	var output string
	imagesCount := f.Headers[uuid].ImagesCountOld
	imageHumanSize := int(f.Headers[uuid].ImagesCountOld) * binary.Size(CacheImageInfo{}) / 1024
	imagesOffset := int(f.Headers[uuid].ImagesOffsetOld)
	imagesSize := int(imagesCount) * binary.Size(CacheImageInfo{})

	if f.Headers[uuid].ImagesOffsetOld == 0 && f.Headers[uuid].ImagesCountOld == 0 {
		imagesCount = f.Headers[uuid].ImagesCount
		imageHumanSize = int(f.Headers[uuid].ImagesCount) * binary.Size(CacheImageInfo{}) / 1024
		imagesOffset = int(f.Headers[uuid].ImagesOffset)
		imagesSize = int(f.Headers[uuid].ImagesCount) * binary.Size(CacheImageInfo{})
	}

	if imagesCount > 0 || imagesOffset > 0 || imagesSize > 0 {
		output = fmt.Sprintf("ImagesText Info:             %3dKB, offset:  0x%09X -> 0x%09X\n", imageHumanSize, imagesOffset, imagesOffset+imagesSize)
	}

	return output
}

func (f *File) getSlideInfo(uuid types.UUID, slideVersion uint32) string {
	var output string
	if f.Headers[uuid].SlideInfoOffsetUnused > 0 {
		output = fmt.Sprintf("Slide Info (v%d):            %4dKB, offset:  0x%09X -> 0x%09X\n",
			slideVersion,
			f.Headers[uuid].SlideInfoSizeUnused/1024,
			f.Headers[uuid].SlideInfoOffsetUnused,
			f.Headers[uuid].SlideInfoOffsetUnused+f.Headers[uuid].SlideInfoSizeUnused)
	}
	return output
}

func (f *File) getBranchPools(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].BranchPoolsOffset > 0 {
		output = fmt.Sprintf("Branch Pool:                 %3dMB, offset:  0x%09X -> 0x%09X\n",
			binary.Size(f.BranchPools),
			f.Headers[uuid].BranchPoolsOffset,
			int(f.Headers[uuid].BranchPoolsOffset)+binary.Size(f.BranchPools))
	}
	return output
}

func (f *File) getAccelerateInfo(uuid types.UUID) string {
	var output string
	if !f.IsDyld4 {
		if f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr > 0 {
			output = fmt.Sprintf("Accelerate Tab:              %3dKB, address: 0x%09X -> 0x%09X\n",
				f.Headers[uuid].AccelerateInfoSizeUnusedOrDyldStartFuncAddr/1024,
				f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr,
				f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr+f.Headers[uuid].AccelerateInfoSizeUnusedOrDyldStartFuncAddr)
		}
	}
	return output
}

func (f *File) getDyldInfo(uuid types.UUID) string {
	var output string
	if f.IsDyld4 {
		output = fmt.Sprintf("\ndyld MachO:    address: 0x%09X\n", f.Headers[uuid].AccelerateInfoAddrUnusedOrDyldAddr)
		output += fmt.Sprintf("_dyld_start:   address: 0x%09X\n", f.Headers[uuid].AccelerateInfoSizeUnusedOrDyldStartFuncAddr)
	}
	return output
}

func (f *File) getPatchInfo(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].PatchInfoAddr > 0 || f.Headers[uuid].PatchInfoSize > 0 {
		output = fmt.Sprintf("Patch Info:                  %3dMB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].PatchInfoSize/(1024*1024),
			f.Headers[uuid].PatchInfoAddr, f.Headers[uuid].PatchInfoAddr+f.Headers[uuid].PatchInfoSize)
	}
	return output
}

func (f *File) getProgClosures(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].ProgClosuresAddr > 0 {
		output = fmt.Sprintf("Closures:                    %3dMB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].ProgClosuresSize/(1024*1024),
			f.Headers[uuid].ProgClosuresAddr,
			f.Headers[uuid].ProgClosuresAddr+f.Headers[uuid].ProgClosuresSize)
	}
	return output
}

func (f *File) getProgClosuresTrie(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].ProgClosuresTrieAddr > 0 {
		output = fmt.Sprintf("Closures Trie:               %3dKB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].ProgClosuresTrieSize/1024,
			f.Headers[uuid].ProgClosuresTrieAddr,
			f.Headers[uuid].ProgClosuresTrieAddr+f.Headers[uuid].ProgClosuresTrieSize)
	}
	return output
}

func (f *File) getPrebuiltLoaderSet(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].DylibsPblSetAddr > 0 {
		output = fmt.Sprintf("Prebuilt Loader Set:         %3dMB, address: 0x%09X -> 0x%09X\n",
			(f.Headers[uuid].ProgramsPblSetPoolAddr-f.Headers[uuid].DylibsPblSetAddr)/1024/1024,
			f.Headers[uuid].DylibsPblSetAddr,
			f.Headers[uuid].ProgramsPblSetPoolAddr-f.Headers[uuid].DylibsPblSetAddr)
	}
	return output
}

func (f *File) getPrebuiltLoaderSetPool(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].ProgramsPblSetPoolAddr > 0 {
		output = fmt.Sprintf("Prebuilt Loader Pool:        %3dMB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].ProgramsPblSetPoolSize/(1024*1024),
			f.Headers[uuid].ProgramsPblSetPoolAddr,
			f.Headers[uuid].ProgramsPblSetPoolAddr+f.Headers[uuid].ProgramsPblSetPoolSize)
	}
	return output
}

func (f *File) getObjcOpts(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].ObjcOptsOffset > 0 {
		output = fmt.Sprintf("ObjC Opts:                    %3dB, offset:  0x%09X -> 0x%09X\n",
			f.Headers[uuid].ObjcOptsSize,
			f.Headers[uuid].ObjcOptsOffset,
			f.Headers[uuid].ObjcOptsOffset+f.Headers[uuid].ObjcOptsSize)
	}
	return output
}

func (f *File) getSwiftOpts(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].SwiftOptsOffset > 0 {
		output = fmt.Sprintf("Swift Opts:                  %3dkB, offset:  0x%09X -> 0x%09X\n",
			f.Headers[uuid].SwiftOptsSize/(1024),
			f.Headers[uuid].SwiftOptsOffset,
			f.Headers[uuid].SwiftOptsOffset+f.Headers[uuid].SwiftOptsSize)
	}
	return output
}

func (f *File) getDynamicConfig(uuid types.UUID) string {
	var output string
	if f.IsDyld4 && f.Headers[uuid].SwiftOptsOffset > 0 {
		output = fmt.Sprintf("Dynamic Config:              %3dkB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].DynamicDataMaxSize/(1024),
			f.Headers[uuid].SharedRegionStart+f.Headers[uuid].DynamicDataOffset,
			f.Headers[uuid].SharedRegionStart+f.Headers[uuid].DynamicDataOffset+f.Headers[uuid].DynamicDataMaxSize)
	}
	return output
}

func (f *File) getSharedRegion(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].SharedRegionSize > 0 {
		output = fmt.Sprintf("Shared Region:               %3dGB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].SharedRegionSize/(1024*1024*1024),
			f.Headers[uuid].SharedRegionStart,
			f.Headers[uuid].SharedRegionStart+f.Headers[uuid].SharedRegionSize)
	}
	return output
}

func (f *File) getCodeSignature(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].CodeSignatureSize > 0 {
		output = fmt.Sprintf("Code Signature: %3dMB, offset:  0x%09X -> 0x%09X\n",
			f.Headers[uuid].CodeSignatureSize/(1024*1024),
			f.Headers[uuid].CodeSignatureOffset,
			f.Headers[uuid].CodeSignatureOffset+f.Headers[uuid].CodeSignatureSize)
	}
	return output
}

func (f *File) getRosetta(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].RosettaReadOnlySize > 0 {
		output += fmt.Sprintf("Rosetta RO:    %s, address: 0x%09X -> 0x%09X\n",
			humanize.Bytes(f.Headers[uuid].RosettaReadOnlySize),
			f.Headers[uuid].RosettaReadOnlyAddr,
			f.Headers[uuid].RosettaReadOnlyAddr+f.Headers[uuid].RosettaReadOnlySize)
	}
	if f.Headers[uuid].RosettaReadWriteSize > 0 {
		output += fmt.Sprintf("Rosetta RW:    %s, address: 0x%09X -> 0x%09X\n",
			humanize.Bytes(f.Headers[uuid].RosettaReadWriteSize),
			f.Headers[uuid].RosettaReadWriteAddr,
			f.Headers[uuid].RosettaReadWriteAddr+f.Headers[uuid].RosettaReadWriteSize)
	}
	return output
}

func (f *File) getMappings(slideVersion uint32, verbose bool) string {
	var output string
	if f.Headers[f.UUID].SlideInfoOffsetUnused > 0 {
		for uuid, cacheMappings := range f.Mappings {
			output += fmt.Sprintf("\n> SubCache %s", uuid)
			output += cacheMappings.String()
		}
	} else {
		// sort mappings map by address
		uuids := make([]types.UUID, 0, len(f.MappingsWithSlideInfo))
		for u := range f.MappingsWithSlideInfo {
			uuids = append(uuids, u)
		}
		sort.SliceStable(uuids, func(i, j int) bool {
			return f.MappingsWithSlideInfo[uuids[i]][0].Address < f.MappingsWithSlideInfo[uuids[j]][0].Address
		})
		for _, uuid := range uuids {
			if uuid == f.symUUID {
				output += fmt.Sprintf("\n> Cache (.symbols) UUID: %s\n\n", uuid)
			} else {
				ext, err := f.GetSubCacheExtensionFromUUID(uuid)
				if err != nil {
					output += fmt.Sprintf("\n> Cache UUID: %s\n\n", uuid)
				} else {
					var stubs string
					if f.Headers[uuid].ImagesCount == 0 && f.Headers[uuid].ImagesCountOld == 0 {
						stubs = "STUB Island "
					}
					output += fmt.Sprintf("\n> %sCache (%s) UUID: %s\n\n", stubs, ext, uuid)
				}
			}
			output += "Mappings\n--------\n\n"
			output += f.MappingsWithSlideInfo[uuid].String(slideVersion, verbose)
			output += fmt.Sprintln()
			output += f.getCodeSignature(uuid)
			output += f.getRosetta(uuid)
		}
	}
	return output
}
