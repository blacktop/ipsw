package dyld

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

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

func (mappings cacheMappingsWithSlideInfo) String(slideVersion uint32) string {
	tableString := &strings.Builder{}

	mdata := [][]string{}
	for _, mapping := range mappings {
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

func (f *File) String() string {
	var slideVersion uint32

	if f.SlideInfo != nil {
		slideVersion = f.SlideInfo.GetVersion()
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
		bytes.Trim(f.Magic[:], "\x00"),
		f.UUID,
		f.Platform,
		f.getFormatVersion(),
		f.getMaxSlide(),
		f.getSubCacheInfo(),
		f.getLocalSymbols(),
		f.getCodeSignature(),
		f.getImagesTextInfo(),
		f.getSlideInfo(slideVersion),
		f.getBranchPools(),
		f.getAccelerateInfo(),
		f.getPatchInfo(),
		f.getProgClosures(),
		f.getProgClosuresTrie(),
		f.getSharedRegion(),
		f.getMappings(slideVersion),
	)
}

func (f *File) getFormatVersion() string {
	var output string
	if f.FormatVersion > 0 {
		output = fmt.Sprintf("Format            = %s\n", f.FormatVersion)
	}
	return output
}

func (f *File) getMaxSlide() string {
	var output string
	if f.MaxSlide > 0 {
		output = fmt.Sprintf("Max Slide         = %s\n", f.MaxSlide)
	}
	return output
}

func (f *File) getSubCacheInfo() string {
	var output string
	if f.ImagesOffset == 0 && f.ImagesCount == 0 {
		if f.SubCachesUUID > 0 {
			var symSCUUID string
			if !f.SymbolsSubCacheUUID.IsNull() {
				symSCUUID = fmt.Sprintf("Sym SubCache UUID = %s\n", f.SymbolsSubCacheUUID)
			}
			output = fmt.Sprintf(
				"Num SubCaches     = %d\n"+
					"SubCache Group ID = %#x\n"+
					"%s",
				f.NumSubCaches,
				f.SubCachesUUID,
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

func (f *File) getCodeSignature() string {
	var output string
	if f.CodeSignatureSize > 0 {
		output = fmt.Sprintf("Code Signature:                 %3dMB, offset:  0x%09X -> 0x%09X\n",
			f.CodeSignatureSize/(1024*1024),
			f.CodeSignatureOffset,
			f.CodeSignatureOffset+f.CodeSignatureSize)
	}
	return output
}

func (f *File) getImagesTextInfo() string {
	var output string
	imagesCount := f.ImagesCount
	imageHumanSize := int(f.ImagesCount) * binary.Size(CacheImageInfo{}) / 1024
	imagesOffset := int(f.ImagesOffset)
	imagesSize := int(imagesCount) * binary.Size(CacheImageInfo{})

	if f.ImagesOffset == 0 && f.ImagesCount == 0 {
		imagesCount = f.ImagesWithSubCachesCount
		imageHumanSize = int(f.ImagesWithSubCachesCount) * binary.Size(CacheImageInfo{}) / 1024
		imagesOffset = int(f.ImagesWithSubCachesOffset)
		imagesSize = int(f.ImagesWithSubCachesCount) * binary.Size(CacheImageInfo{})
	}

	if imagesCount > 0 || imagesOffset > 0 || imagesSize > 0 {
		output = fmt.Sprintf("ImagesText Info (%3d entries): %3dKB, offset:  0x%09X -> 0x%09X\n", imagesCount, imageHumanSize, imagesOffset, imagesOffset+imagesSize)
	}

	return output
}

func (f *File) getSlideInfo(slideVersion uint32) string {
	var output string
	if f.SlideInfoOffsetUnused > 0 {
		output = fmt.Sprintf("Slide Info (v%d):               %4dKB, offset:  0x%09X -> 0x%09X\n",
			slideVersion,
			f.SlideInfoSizeUnused/1024,
			f.SlideInfoOffsetUnused,
			f.SlideInfoOffsetUnused+f.SlideInfoSizeUnused)
	}
	return output
}

func (f *File) getBranchPools() string {
	var output string
	if f.BranchPoolsOffset > 0 {
		output = fmt.Sprintf("Branch Pool:                    %3dMB, offset:  0x%09X -> 0x%09X\n",
			binary.Size(f.BranchPools),
			f.BranchPoolsOffset,
			int(f.BranchPoolsOffset)+binary.Size(f.BranchPools))
	}
	return output
}

func (f *File) getAccelerateInfo() string {
	var output string
	if f.AccelerateInfoAddr > 0 {
		output = fmt.Sprintf("Accelerate Tab:                 %3dKB, address: 0x%09X -> 0x%09X\n",
			f.AccelerateInfoSize/1024,
			f.AccelerateInfoAddr,
			f.AccelerateInfoAddr+f.AccelerateInfoSize)
	}
	return output
}

func (f *File) getPatchInfo() string {
	var output string
	if f.PatchInfoAddr > 0 || f.PatchInfoSize > 0 {
		output = fmt.Sprintf("Patch Info:                     %3dMB, address: 0x%09X -> 0x%09X\n",
			f.PatchInfoSize/(1024*1024),
			f.PatchInfoAddr, f.PatchInfoAddr+f.PatchInfoSize)
	}
	return output
}

func (f *File) getProgClosures() string {
	var output string
	if f.ProgClosuresAddr > 0 {
		output = fmt.Sprintf("Closures:                       %3dMB, address: 0x%09X -> 0x%09X\n",
			f.ProgClosuresSize/(1024*1024),
			f.ProgClosuresAddr,
			f.ProgClosuresAddr+f.ProgClosuresSize)
	} else if f.ProgClosuresWithSubCachesAddr > 0 {
		output = fmt.Sprintf("Closures:                       %3dMB, address: 0x%09X -> 0x%09X\n",
			f.ProgClosuresWithSubCachesSize/(1024*1024),
			f.ProgClosuresWithSubCachesAddr,
			f.ProgClosuresWithSubCachesAddr+f.ProgClosuresWithSubCachesSize)
	}
	return output
}

func (f *File) getProgClosuresTrie() string {
	var output string
	if f.ProgClosuresTrieAddr > 0 {
		output = fmt.Sprintf("Closures Trie:                  %3dKB, address: 0x%09X -> 0x%09X\n",
			f.ProgClosuresTrieSize/1024,
			f.ProgClosuresTrieAddr,
			f.ProgClosuresTrieAddr+f.ProgClosuresTrieSize)
	} else if f.ProgClosuresTrieWithSubCachesAddr > 0 {
		output = fmt.Sprintf("Closures Trie:                  %3dKB, address: 0x%09X -> 0x%09X\n",
			f.ProgClosuresTrieWithSubCachesSize/1024,
			f.ProgClosuresTrieWithSubCachesAddr,
			f.ProgClosuresTrieWithSubCachesAddr+uint64(f.ProgClosuresTrieWithSubCachesSize))
	}
	return output
}

func (f *File) getSharedRegion() string {
	var output string
	if f.SharedRegionSize > 0 {
		output = fmt.Sprintf("Shared Region:                  %3dGB, address: 0x%09X -> 0x%09X\n",
			f.SharedRegionSize/(1024*1024*1024),
			f.SharedRegionStart,
			f.SharedRegionStart+f.SharedRegionSize)
	}
	return output
}

func (f *File) getMappings(slideVersion uint32) string {
	var output string
	if f.CacheHeader.SlideInfoOffsetUnused > 0 {
		output = f.Mappings.String()
	} else {
		output = f.MappingsWithSlideInfo.String(slideVersion)
	}
	return output
}
