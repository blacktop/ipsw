package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
		dch.ImagesOffset,
		dch.ImagesCount,
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

func (self CacheMappingInfo) String() string {
	return fmt.Sprintf(
		"Address    = %016X\n"+
			"Size       = %s\n"+
			"FileOffset = %X\n"+
			"MaxProt    = %s\n"+
			"InitProt   = %s\n",
		self.Address,
		humanize.Bytes(self.Size),
		self.FileOffset,
		self.MaxProt.String(),
		self.InitProt.String(),
	)
}

func (self CacheImageInfo) String() string {
	return fmt.Sprintf(
		"Address        = %016X\n"+
			"ModTime        = %016X\n"+
			"Inode          = %d\n"+
			"PathFileOffset = %08X\n",
		self.Address,
		self.ModTime,
		self.Inode,
		self.PathFileOffset,
	)
}

func (dch CacheHeader) Print() {
	fmt.Println("Header")
	fmt.Println("======")
	fmt.Println(dch.String())
	fmt.Printf("Slide Info:     %4dKB,  file offset: 0x%09X -> 0x%09X\n", dch.SlideInfoSizeUnused/1024, dch.SlideInfoOffsetUnused, dch.SlideInfoOffsetUnused+dch.SlideInfoSizeUnused)
	fmt.Printf("Local Symbols:  %3dMB,  file offset: 0x%09X -> 0x%09X\n", dch.LocalSymbolsSize/(1024*1024), dch.LocalSymbolsOffset, dch.LocalSymbolsOffset+dch.LocalSymbolsSize)
	fmt.Printf("Accelerate Tab: %3dKB,  address: 0x%09X -> 0x%09X\n", dch.AccelerateInfoSize/1024, dch.AccelerateInfoAddr, dch.AccelerateInfoAddr+dch.AccelerateInfoSize)
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
		if verbose {
			mappingAddr = fmt.Sprintf("%#08x -> %#08x", mapping.Address, mapping.Address+mapping.Size)
			mappingOff = fmt.Sprintf("%#08x -> %#08x", mapping.FileOffset, mapping.FileOffset+mapping.Size)
		}
		var slideInfoSize string
		if mapping.SlideInfoSize > 0 {
			slideInfoSize = fmt.Sprintf("%#08x -> %#08x", mapping.SlideInfoOffset, mapping.SlideInfoOffset+mapping.SlideInfoSize)
		}
		mdata = append(mdata, []string{
			mapping.Name,
			mapping.InitProt.String(),
			mapping.MaxProt.String(),
			fmt.Sprintf("%#08x (%s)", mapping.Size, humanize.Bytes(mapping.Size)),
			mappingAddr,
			mappingOff,
			slideInfoSize,
			fmt.Sprintf("%d", mapping.Flags),
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
		slideVersion = f.SlideInfo[f.UUID].GetVersion()
	}

	return fmt.Sprintf(
		"Header\n"+
			"======\n"+
			"Magic             = \"%s\"\n"+
			"UUID              = %s\n"+
			"Platform          = %s\n"+
			"%s"+ // format
			"%s"+ // max slide
			"%s\n"+ // sub cache info
			"%s"+ // local symbols
			"%s"+ // code signature
			"%s"+ // image text info
			"%s"+ // slideInfo
			"%s"+ // branchPools
			"%s"+ // accelerateInfo
			"%s"+ // patch info
			"%s"+ // progClosures
			"%s"+ // progClosuresTrie
			"%s"+ // shared region
			"\nMappings\n"+
			"========\n"+
			"%s",
		f.Headers[f.UUID].Magic.String(),
		f.UUID,
		f.Headers[f.UUID].Platform,
		f.getFormatVersion(f.UUID),
		f.getMaxSlide(f.UUID),
		f.getSubCacheInfo(),
		f.getLocalSymbols(),
		f.getCodeSignature(f.UUID), // TODO: show ALL subcache's code signature blocks
		f.getImagesTextInfo(f.UUID),
		f.getSlideInfo(f.UUID, slideVersion),
		f.getBranchPools(f.UUID),
		f.getAccelerateInfo(f.UUID),
		f.getPatchInfo(f.UUID),
		f.getProgClosures(f.UUID),
		f.getProgClosuresTrie(f.UUID),
		f.getSharedRegion(f.UUID),
		f.getMappings(slideVersion, verbose),
	)
}

func (f *File) getFormatVersion(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].FormatVersion > 0 {
		output = fmt.Sprintf("Format            = %s\n", f.Headers[uuid].FormatVersion)
	}
	return output
}

func (f *File) getMaxSlide(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].MaxSlide > 0 {
		output = fmt.Sprintf("Max Slide         = %s\n", f.Headers[uuid].MaxSlide)
	}
	return output
}

func (f *File) getSubCacheInfo() string {
	var output string
	if f.IsDyld4 {
		if f.Headers[f.UUID].SubCachesUUID > 0 {
			var symSCUUID string
			if !f.Headers[f.UUID].SymbolsSubCacheUUID.IsNull() {
				symSCUUID = fmt.Sprintf("Symbol Cache UUID = %s\n", f.Headers[f.UUID].SymbolsSubCacheUUID)
			}
			output = fmt.Sprintf(
				"Num SubCaches     = %d\n"+
					"SubCache Group ID = %#x\n"+
					"%s",
				f.Headers[f.UUID].NumSubCaches,
				f.Headers[f.UUID].SubCachesUUID,
				symSCUUID,
			)
		}
	}
	return output
}

func (f *File) getLocalSymbols() string {
	var output string
	if f.LocalSymInfo.NListFileOffset > 0 && f.LocalSymInfo.StringsFileOffset > 0 {
		output = fmt.Sprintf(
			"Local Symbols (nlist array):    %3dMB, offset:  0x%09X -> 0x%09X\n"+
				"Local Symbols (string pool):    %3dMB, offset:  0x%09X -> 0x%09X\n",
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

func (f *File) getCodeSignature(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].CodeSignatureSize > 0 {
		output = fmt.Sprintf("Code Signature:                 %3dMB, offset:  0x%09X -> 0x%09X\n",
			f.Headers[uuid].CodeSignatureSize/(1024*1024),
			f.Headers[uuid].CodeSignatureOffset,
			f.Headers[uuid].CodeSignatureOffset+f.Headers[uuid].CodeSignatureSize)
	}
	return output
}

func (f *File) getImagesTextInfo(uuid types.UUID) string {
	var output string
	imagesCount := f.Headers[uuid].ImagesCount
	imageHumanSize := int(f.Headers[uuid].ImagesCount) * binary.Size(CacheImageInfo{}) / 1024
	imagesOffset := int(f.Headers[uuid].ImagesOffset)
	imagesSize := int(imagesCount) * binary.Size(CacheImageInfo{})

	if f.Headers[uuid].ImagesOffset == 0 && f.Headers[uuid].ImagesCount == 0 {
		imagesCount = f.Headers[uuid].ImagesWithSubCachesCount
		imageHumanSize = int(f.Headers[uuid].ImagesWithSubCachesCount) * binary.Size(CacheImageInfo{}) / 1024
		imagesOffset = int(f.Headers[uuid].ImagesWithSubCachesOffset)
		imagesSize = int(f.Headers[uuid].ImagesWithSubCachesCount) * binary.Size(CacheImageInfo{})
	}

	if imagesCount > 0 || imagesOffset > 0 || imagesSize > 0 {
		output = fmt.Sprintf("ImagesText Info (%3d entries): %3dKB, offset:  0x%09X -> 0x%09X\n", imagesCount, imageHumanSize, imagesOffset, imagesOffset+imagesSize)
	}

	return output
}

func (f *File) getSlideInfo(uuid types.UUID, slideVersion uint32) string {
	var output string
	if f.Headers[uuid].SlideInfoOffsetUnused > 0 {
		output = fmt.Sprintf("Slide Info (v%d):               %4dKB, offset:  0x%09X -> 0x%09X\n",
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
		output = fmt.Sprintf("Branch Pool:                    %3dMB, offset:  0x%09X -> 0x%09X\n",
			binary.Size(f.BranchPools),
			f.Headers[uuid].BranchPoolsOffset,
			int(f.Headers[uuid].BranchPoolsOffset)+binary.Size(f.BranchPools))
	}
	return output
}

func (f *File) getAccelerateInfo(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].AccelerateInfoAddr > 0 {
		output = fmt.Sprintf("Accelerate Tab:                 %3dKB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].AccelerateInfoSize/1024,
			f.Headers[uuid].AccelerateInfoAddr,
			f.Headers[uuid].AccelerateInfoAddr+f.Headers[uuid].AccelerateInfoSize)
	}
	return output
}

func (f *File) getPatchInfo(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].PatchInfoAddr > 0 || f.Headers[uuid].PatchInfoSize > 0 {
		output = fmt.Sprintf("Patch Info:                     %3dMB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].PatchInfoSize/(1024*1024),
			f.Headers[uuid].PatchInfoAddr, f.Headers[uuid].PatchInfoAddr+f.Headers[uuid].PatchInfoSize)
	}
	return output
}

func (f *File) getProgClosures(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].ProgClosuresAddr > 0 {
		output = fmt.Sprintf("Closures:                       %3dMB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].ProgClosuresSize/(1024*1024),
			f.Headers[uuid].ProgClosuresAddr,
			f.Headers[uuid].ProgClosuresAddr+f.Headers[uuid].ProgClosuresSize)
	} else if f.Headers[uuid].ProgClosuresWithSubCachesAddr > 0 {
		output = fmt.Sprintf("Closures:                       %3dMB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].ProgClosuresWithSubCachesSize/(1024*1024),
			f.Headers[uuid].ProgClosuresWithSubCachesAddr,
			f.Headers[uuid].ProgClosuresWithSubCachesAddr+f.Headers[uuid].ProgClosuresWithSubCachesSize)
	}
	return output
}

func (f *File) getProgClosuresTrie(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].ProgClosuresTrieAddr > 0 {
		output = fmt.Sprintf("Closures Trie:                  %3dKB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].ProgClosuresTrieSize/1024,
			f.Headers[uuid].ProgClosuresTrieAddr,
			f.Headers[uuid].ProgClosuresTrieAddr+f.Headers[uuid].ProgClosuresTrieSize)
	} else if f.Headers[uuid].ProgClosuresTrieWithSubCachesAddr > 0 {
		output = fmt.Sprintf("Closures Trie:                  %3dKB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].ProgClosuresTrieWithSubCachesSize/1024,
			f.Headers[uuid].ProgClosuresTrieWithSubCachesAddr,
			f.Headers[uuid].ProgClosuresTrieWithSubCachesAddr+uint64(f.Headers[uuid].ProgClosuresTrieWithSubCachesSize))
	}
	return output
}

func (f *File) getSharedRegion(uuid types.UUID) string {
	var output string
	if f.Headers[uuid].SharedRegionSize > 0 {
		output = fmt.Sprintf("Shared Region:                  %3dGB, address: 0x%09X -> 0x%09X\n",
			f.Headers[uuid].SharedRegionSize/(1024*1024*1024),
			f.Headers[uuid].SharedRegionStart,
			f.Headers[uuid].SharedRegionStart+f.Headers[uuid].SharedRegionSize)
	}
	return output
}

func (f *File) getMappings(slideVersion uint32, verbose bool) string {
	var output string
	if f.Headers[f.UUID].SlideInfoOffsetUnused > 0 {
		for uuid, cacheMappings := range f.Mappings {
			if uuid != f.UUID {
				output += fmt.Sprintf("\n> SubCache %s", uuid)
			}
			output += cacheMappings.String()
		}
	} else {
		for uuid, cacheMappings := range f.MappingsWithSlideInfo {
			if uuid != f.UUID {
				output += fmt.Sprintf("\n> SubCache %s\n", uuid)
			}
			output += cacheMappings.String(slideVersion, verbose)
		}
	}
	return output
}
