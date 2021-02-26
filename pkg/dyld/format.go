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

	mdata = append(mdata, []string{
		mapping.Name,
		mapping.InitProt.String(),
		mapping.MaxProt.String(),
		fmt.Sprintf("%d MB", mapping.Size/(1024*1024)),
		// humanize.Bytes(mapping.Size),
		fmt.Sprintf("%#08x -> %#08x", mapping.Address, mapping.Address+mapping.Size),
		fmt.Sprintf("%#08x -> %#08x", mapping.FileOffset, mapping.FileOffset+mapping.Size),
		fmt.Sprintf("%#08x -> %#08x", mapping.SlideInfoOffset, mapping.SlideInfoOffset+mapping.SlideInfoSize),
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

func (mappings cacheMappingsWithSlideInfo) String() string {
	tableString := &strings.Builder{}

	mdata := [][]string{}
	for _, mapping := range mappings {
		mdata = append(mdata, []string{
			mapping.Name,
			mapping.InitProt.String(),
			mapping.MaxProt.String(),
			fmt.Sprintf("%d MB", mapping.Size/(1024*1024)),
			// humanize.Bytes(mapping.Size),
			fmt.Sprintf("%#08x -> %#08x", mapping.Address, mapping.Address+mapping.Size),
			fmt.Sprintf("%#08x -> %#08x", mapping.FileOffset, mapping.FileOffset+mapping.Size),
			fmt.Sprintf("%#08x -> %#08x", mapping.SlideInfoOffset, mapping.SlideInfoOffset+mapping.SlideInfoSize),
			fmt.Sprintf("%d", mapping.Flags),
		})
	}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Seg", "InitProt", "MaxProt", "Size", "Address", "File Offset", "Slide Info Offset", "Flags"})
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
	var mappings string
	if f.SlideInfo != nil {
		slideVersion = f.SlideInfo.GetVersion()
	} else {
		slideVersion = 0
	}
	if f.CacheHeader.SlideInfoOffsetUnused > 0 {
		mappings = f.Mappings.String()
	} else {
		mappings = f.MappingsWithSlideInfo.String()
	}
	return fmt.Sprintf(
		"Header\n"+
			"======\n"+
			"Magic            = \"%s\"\n"+
			"UUID             = %s\n"+
			"Platform         = %s\n"+
			"Format           = %s\n"+
			"Max Slide        = %s\n\n"+
			"Local Symbols (nlist array):    %3dMB,  offset:  0x%09X -> 0x%09X\n"+
			"Local Symbols (string pool):    %3dMB,  offset:  0x%09X -> 0x%09X\n"+
			"Code Signature:                 %3dMB,  offset:  0x%09X -> 0x%09X\n"+
			"ImagesText Info (%3d entries): %3dKB,  offset:  0x%09X -> 0x%09X\n"+
			"Slide Info (v%d):               %4dKB,  offset:  0x%09X -> 0x%09X\n"+
			"Branch Pool:                    %3dMB,  offset:  0x%09X -> 0x%09X\n"+
			"Accelerate Tab:                 %3dKB,  address: 0x%09X -> 0x%09X\n"+
			"Patch Info:                     %3dKB,  address: 0x%09X -> 0x%09X\n"+
			"Closures:                       %3dMB,  address: 0x%09X -> 0x%09X\n"+
			"Closures Trie:                  %3dKB,  address: 0x%09X -> 0x%09X\n"+
			"Shared Region:                  %3dGB,  address: 0x%09X -> 0x%09X\n"+
			"\nMappings\n"+
			"========\n"+
			"%s",
		bytes.Trim(f.Magic[:], "\x00"),
		f.UUID,
		f.Platform,
		f.FormatVersion,
		f.MaxSlide,
		f.LocalSymInfo.NListByteSize/(1024*1024), f.LocalSymInfo.NListFileOffset, f.LocalSymInfo.NListFileOffset+f.LocalSymInfo.NListByteSize,
		f.LocalSymInfo.StringsSize/(1024*1024), f.LocalSymInfo.StringsFileOffset, f.LocalSymInfo.StringsFileOffset+f.LocalSymInfo.StringsSize,
		f.CodeSignatureSize/(1024*1024), f.CodeSignatureOffset, f.CodeSignatureOffset+f.CodeSignatureSize,
		f.ImagesCount, int(f.ImagesCount)*binary.Size(CacheImageInfo{})/1024, f.ImagesOffset, int(f.ImagesOffset)+int(f.ImagesCount)*binary.Size(CacheImageInfo{}),
		slideVersion, f.SlideInfoSizeUnused/1024, f.SlideInfoOffsetUnused, f.SlideInfoOffsetUnused+f.SlideInfoSizeUnused,
		binary.Size(f.BranchPools), f.BranchPoolsOffset, int(f.BranchPoolsOffset)+binary.Size(f.BranchPools),
		f.AccelerateInfoSize/1024, f.AccelerateInfoAddr, f.AccelerateInfoAddr+f.AccelerateInfoSize,
		f.PatchInfoSize/1024, f.PatchInfoAddr, f.PatchInfoAddr+f.PatchInfoSize,
		f.ProgClosuresSize/(1024*1024), f.ProgClosuresAddr, f.ProgClosuresAddr+f.ProgClosuresSize,
		f.ProgClosuresTrieSize/1024, f.ProgClosuresTrieAddr, f.ProgClosuresTrieAddr+f.ProgClosuresTrieSize,
		f.SharedRegionSize/(1024*1024*1024), f.SharedRegionStart, f.SharedRegionStart+f.SharedRegionSize,
		mappings,
	)
}
