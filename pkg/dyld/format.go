package dyld

import (
	"bytes"
	"fmt"
	"os"

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
		dch.SlideInfoOffset,
		dch.SlideInfoSize,
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
	fmt.Printf("Slide Info:    %4dKB,  file offset: 0x%08X -> 0x%08X\n", dch.SlideInfoSize/1024, dch.SlideInfoOffset, dch.SlideInfoOffset+dch.SlideInfoSize)
	fmt.Printf("Local Symbols:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", dch.LocalSymbolsSize/(1024*1024), dch.LocalSymbolsOffset, dch.LocalSymbolsOffset+dch.LocalSymbolsSize)
	fmt.Printf("Accelerate Tab: %3dKB,                                          address: 0x%08X -> 0x%08X\n", dch.AccelerateInfoSize/1024, dch.AccelerateInfoAddr, dch.AccelerateInfoAddr+dch.AccelerateInfoSize)
	fmt.Println()
}

func (mappings cacheMappings) Print() {
	fmt.Println("Mappings")
	fmt.Println("========")
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
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Seg", "InitProt", "MaxProt", "Size", "Address", "File Offset"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(mdata)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render() // Send output
	fmt.Println()
}

func (images cacheImages) Print() {
	fmt.Println("Images")
	fmt.Println("======")
	for idx, image := range images {
		fmt.Printf("%d:\t%08x %s\n", idx+1, image.Info.Address, image.Name)
	}
}

func (info CacheSlideInfo) Print() {

}
