package kernelcache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// KextList lists all the kernel extensions in the kernelcache
func KextList(kernel string) error {
	kc, err := NewKernelCache(kernel)
	if err != nil {
		return err
	}
	defer kc.Close()

	prelink, err := kc.PrelinkInfoDict()
	if err != nil {
		return err
	}

	fmt.Println("FOUND:", len(prelink.PrelinkInfoDictionary))
	prelink.ForeachBundle(func(bundle * CFBundle) error {
		fmt.Printf("%s (%s)\n", bundle.ID, bundle.Version)
		return nil
	})

	return nil
}

// unSeek performs thingy() and seeks fh back to its position before thingy() was performed.
func unSeek(fh * os.File, thingy func() error) error {
	var startSeek int64
	var err error
	if startSeek, err = fh.Seek(0, io.SeekCurrent); err != nil {
		return err
	}

	err = thingy()

	if _, seekBackErr := fh.Seek(startSeek, io.SeekStart); seekBackErr != nil {
		return seekBackErr
	}

	return err
}

type Segment64 struct {
	LoadCmd	  uint32
	Len       uint32
	Name      [16]byte
	Addr      uint64
	Memsz     uint64
	Offset    uint64
	Filesz    uint64
	Maxprot   uint32
	Prot      uint32
	Nsect     uint32
	Flag      uint32
}

type Section64 struct {
	Name      [16]byte
	Seg       [16]byte
	Addr      uint64
	Size      uint64
	Offset    uint32
	Align     uint32
	Reloff    uint32
	Nreloc    uint32
	Flags     uint32
	Reserved1 uint32
	Reserved2 uint32
	Reserved3 uint32
}

func roundUp64(x, y uint64) uint64 {
	return (x + y) & (^(y - 1))
}

// ExtractKext locates the specified kext and writes it to a file with the same name.
func ExtractKext(kernel, kextName string) error {
	fh, err := os.Create(kextName)
	if err != nil {
		return err
	}

	defer fh.Close()

	kc, err := NewKernelCache(kernel)
	if err != nil {
		return err
	}

	defer kc.Close()

	kext, err := kc.KextWithName(kextName)
	if err != nil {
		return err
	}

	plkOffsets, err := kc.PrelinkOffsets()
	if err != nil {
		return err
	}

	/*
	 * How to write a kext in 2 easy steps: 
	 *   One: Iterate over the segs, write them out (text includes MH and segs!)
	 *   Two: Go back and fix the segments and sections (Slide the offsets so
	 *        that the next tool to read them will work)
	 */


	fmt.Println("Copying Segment data...")
	fmt.Println()

	var segOffset uint64
	segOffsets := make([]uint64, 0)
	for _, seg := range kext.Segments() {
		fmt.Printf("%16s: Offset [0x%.16x -> ", seg.Name, seg.Offset)

		seg.Offset = plkOffsets.SlideOffset(seg.Name, seg.Addr)
		fmt.Printf("0x%.16x (0x%.16x)] %d bytes\n", seg.Offset, segOffset, seg.Filesz)

		// round the segment's on-disk size up to 4096
		segDiskSize := roundUp64(seg.Filesz, 0x1000)
		segDatum := make([]byte, segDiskSize)
		if seg.Name != "__LINKEDIT" {
			if n, err := kc.Reader().ReadAt(segDatum[:seg.Filesz], int64(seg.Offset)); n != int(seg.Filesz) {
				fmt.Printf("  Couldn't read segment data at %x: %v", seg.Offset, err)
			}
		}

		if n, err := fh.Write(segDatum); n != len(segDatum) {
			fmt.Printf("Couldn't write segment data: %v", err)
			return err
		}

		segOffsets = append(segOffsets, uint64(segOffset))
		segOffset += segDiskSize
	}

	fmt.Println()
	fmt.Println("Fixing segment and section offsets...")
	fmt.Println()

	// Seek passed the mach-o header.
	var mhSize int64 = 8 * 4
	if _, err := fh.Seek(mhSize, io.SeekStart); err != nil {
		return err
	}

	for i := 0; i < len(segOffsets); i++ {
		var segHeader Segment64
		err := unSeek(fh, func() error {
			if err2 := binary.Read(fh, binary.LittleEndian, &segHeader); err2 != nil {
				fmt.Printf("Couldn't read segment header: %v\n", err2)
				return err2
			}	
			return nil
		})
	
		if err != nil {
			fmt.Printf("Failed to read segment header: %v\n", err)
			return err
		}
		
		origOffset := segHeader.Offset
		segHeader.Offset = segOffsets[i]
		offsetDelta := segHeader.Offset - origOffset
		
		if err = binary.Write(fh, binary.LittleEndian, &segHeader); err != nil {
			fmt.Printf("Failed to write segment header: %v", err)
			return err
		}

		for i := 0; i < int(segHeader.Nsect); i++ {
			var sectHeader Section64

			err = unSeek(fh, func() error {
				if err2 := binary.Read(fh, binary.LittleEndian, &sectHeader); err2 != nil {
					fmt.Printf("Couldn't read section header: %v\n", err2)
					return err2
				}
				return nil
			})

			if err != nil {
				fmt.Printf("Failed to read section header: %v", err)
				return err
			}

			// DATA/bss has an offset of 0, it's not mapped from the file, so don't add an offset to it.
			usedDelta := offsetDelta
			if sectHeader.Offset == 0 {
				usedDelta = 0
			}

			fmt.Printf("%16s, %16s:  Offset 0x%.16x + 0x%.16x -> ",
				string(bytes.Trim(segHeader.Name[:], "\x00")),
				string(bytes.Trim(sectHeader.Name[:], "\x00")),
				sectHeader.Offset,
				usedDelta)

			sectHeader.Offset += uint32(usedDelta)
			fmt.Printf("0x%.16x\n", sectHeader.Offset)

			if err = binary.Write(fh, binary.LittleEndian, &sectHeader); err != nil {
				fmt.Printf("Failed to write section header: %v\n", err)
				return err
			}
		}
	}

	fmt.Println()

	return nil
}
