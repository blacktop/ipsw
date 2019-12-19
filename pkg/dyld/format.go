package dyld

import (
	"bytes"
	"fmt"
	"os"

	"github.com/dustin/go-humanize"
	"github.com/olekukonko/tablewriter"
)

func (u uuid) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[0], u[1], u[2], u[3],
		u[4], u[5], u[6], u[7],
		u[8], u[9], u[10], u[11],
		u[12], u[13], u[14], u[15])
}

// func (p platform) String() string {
// 	names := [...]string{
// 		"unknown",
// 		"macOS",
// 		"iOS",
// 		"tvOS",
// 		"watchOS",
// 		"bridgeOS",
// 		"iOSMac",
// 		"iOS Simulator",
// 		"tvOS Simulator",
// 		"watchOS Simulator"}
// 	return names[p]
// }

func (v vmProtection) String() string {
	var protStr string
	if v.Read() {
		protStr += "r"
	} else {
		protStr += "-"
	}
	if v.Write() {
		protStr += "w"
	} else {
		protStr += "-"
	}
	if v.Execute() {
		protStr += "x"
	} else {
		protStr += "-"
	}
	return protStr
}

func (dch DyldCacheHeader) String() string {
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
		dch.FormatVersion,
	)
}

func (self DyldCacheMappingInfo) String() string {
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

func (self DyldCacheImageInfo) String() string {
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

func (dch DyldCacheHeader) Print() {
	fmt.Println("Header")
	fmt.Println("======")
	fmt.Println(dch.String())
	fmt.Printf("Slide Info:    %4dKB,  file offset: 0x%08X -> 0x%08X\n", dch.SlideInfoSize/1024, dch.SlideInfoOffset, dch.SlideInfoOffset+dch.SlideInfoSize)
	fmt.Printf("Local Symbols:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", dch.LocalSymbolsSize/(1024*1024), dch.LocalSymbolsOffset, dch.LocalSymbolsOffset+dch.LocalSymbolsSize)
	fmt.Printf("Accelerate Tab: %3dKB,                                          address: 0x%08X -> 0x%08X\n", dch.AccelerateInfoSize/1024, dch.AccelerateInfoAddr, dch.AccelerateInfoAddr+dch.AccelerateInfoSize)
	fmt.Println()
}

func (mappings DyldCacheMappings) Print() {
	fmt.Println("Mappings")
	fmt.Println("========")
	mdata := [][]string{}
	for _, mapping := range mappings {
		mdata = append(mdata, []string{
			mapping.InitProt.String(),
			mapping.MaxProt.String(),
			fmt.Sprintf("%d MB", mapping.Size/(1024*1024)),
			// humanize.Bytes(mapping.Size),
			fmt.Sprintf("%08X -> %08X", mapping.Address, mapping.Address+mapping.Size),
			fmt.Sprintf("%08X -> %08X", mapping.FileOffset, mapping.FileOffset+mapping.Size),
		})
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"InitProt", "MaxProt", "Size", "Address", "File Offset"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.AppendBulk(mdata)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.Render() // Send output
	fmt.Println()
}

func (images DyldCacheImages) Print() {
	fmt.Println("Images")
	fmt.Println("======")
	for idx, image := range images {
		fmt.Printf("%d:\t%08x %s\n", idx+1, image.Info.Address, image.Name)
	}
}

func (info DyldCacheSlideInfo) Print() {

}
