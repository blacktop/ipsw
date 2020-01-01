package dyld

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/macho"
	"github.com/pkg/errors"
)

// Parse parses a dyld_share_cache
func Parse(dsc string, verbose bool) error {

	cache := Cache{}

	file, err := os.Open(dsc)
	if err != nil {
		return errors.Wrapf(err, "failed to open file: %s", dsc)
	}
	defer file.Close()

	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &cache.header); err != nil {
		return err
	}

	file.Seek(int64(cache.header.MappingOffset), os.SEEK_SET)
	hr := bufio.NewReader(file)

	for i := uint32(0); i != cache.header.MappingCount; i++ {
		mapping := CacheMappingInfo{}
		if err := binary.Read(hr, binary.LittleEndian, &mapping); err != nil {
			return err
		}
		cache.mappings = append(cache.mappings, mapping)
	}

	file.Seek(int64(cache.header.ImagesOffset), os.SEEK_SET)
	ir := bufio.NewReader(file)

	for i := uint32(0); i != cache.header.ImagesCount; i++ {
		iinfo := CacheImageInfo{}
		if err := binary.Read(ir, binary.LittleEndian, &iinfo); err != nil {
			return err
		}
		cache.images = append(cache.images, CacheImage{Info: iinfo})
	}
	for idx, image := range cache.images {
		file.Seek(int64(image.Info.PathFileOffset), os.SEEK_SET)

		r := bufio.NewReader(file)
		if name, err := r.ReadString(byte(0)); err == nil {
			cache.images[idx].Name = fmt.Sprintf("%s", bytes.Trim([]byte(name), "\x00"))
		}
	}

	// file.Seek(int64(cache.header.CodeSignatureOffset), os.SEEK_SET)

	// data := make([]byte, cache.header.CodeSignatureSize)
	// if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
	// 	return err
	// }
	// cache.codesignature = data

	// err = ioutil.WriteFile("dyld_codesignature.blob", data, 0644)
	// if err != nil {
	// 	return errors.Wrapf(err, "failed to open file: %s", dsc)
	// }

	// textMapping := cache.mappings[0]
	dataMapping := cache.mappings[1]
	// linkEditMapping := cache.mappings[2]
	// file.Seek(int64((cache.header.SlideInfoOffset-linkEditMapping.FileOffset)+(linkEditMapping.Address-textMapping.Address)), os.SEEK_SET)
	file.Seek(int64(cache.header.SlideInfoOffset), os.SEEK_SET)
	slideInfoVersionData := make([]byte, 4)
	file.Read(slideInfoVersionData)
	slideInfoVersion := binary.LittleEndian.Uint32(slideInfoVersionData)

	file.Seek(int64(cache.header.SlideInfoOffset), os.SEEK_SET)

	switch slideInfoVersion {
	case 1:
		slideInfo := CacheSlideInfo{}
		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
			return err
		}
		cache.slideInfo = slideInfo
	case 2:
		slideInfo := CacheSlideInfo2{}
		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
			return err
		}
		cache.slideInfo = slideInfo
	case 3:
		slideInfo := CacheSlideInfo3{}
		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
			return err
		}
		cache.slideInfo = slideInfo
		PageStarts := make([]uint16, slideInfo.PageStartsCount)
		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &PageStarts); err != nil {
			return err
		}
		fmt.Printf("page_size         =%d\n", slideInfo.PageSize)
		fmt.Printf("page_starts_count =%d\n", slideInfo.PageStartsCount)
		fmt.Printf("auth_value_add    =0x%016X\n", slideInfo.AuthValueAdd)
		dataSegmentStart := dataMapping.FileOffset
		var pointerBytes []byte
		var value CacheSlidePointer3
		for idx, start := range PageStarts {
			pageStart := dataSegmentStart + uint64(uint32(idx)*slideInfo.PageSize)
			pointerBytes = make([]byte, 8)
			if start == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
				fmt.Printf("page[% 5d]: no rebasing\n", idx)
				continue
			}
			fmt.Printf("page[% 5d]: start=0x%04X, addr=0x%04X\n", idx, start, pageStart)
			file.Seek(int64(pageStart), os.SEEK_SET)
			if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &pointerBytes); err != nil {
				return err
			}
			num := binary.LittleEndian.Uint64(pointerBytes)
			value = CacheSlidePointer3(num)
			fmt.Printf("PointerValue           = 0x%016X\n", value.PointerValue())
			fmt.Printf("OffsetToNextPointer    = 0x%016X\n", value.OffsetToNextPointer())
			fmt.Println("authenticated:      ", value.authenticated())
			fmt.Println("hasAddressDiversity:", value.hasAddressDiversity())
			// rebaseLocation := pageStart
			// delta := uint64(start)
			// for {
			// 	rebaseLocation += delta
			// 	value = CacheSlidePointer3(rebaseLocation)
			// 	delta = uint64(((value & 0x3FF8000000000000) >> 51) * 8)

			// 	// Regular pointer which needs to fit in 51-bits of value.
			// 	// C++ RTTI uses the top bit, so we'll allow the whole top-byte
			// 	// and the signed-extended bottom 43-bits to be fit in to 51-bits.
			// 	top8Bits := value & 0x007F80000000000
			// 	bottom43Bits := value & 0x000007FFFFFFFFFF
			// 	targetValue := (top8Bits << 13) | ((CacheSlidePointer3(bottom43Bits<<21) >> 21) & 0x00FFFFFFFFFFFFFF)
			// 	fmt.Printf("    [% 5d + 0x%04X]: 0x%016X\n", idx, (uint64)(rebaseLocation-pageStart), targetValue)
			// 	if delta != 0 {
			// 		break
			// 	}
			// }
		}
	case 4:
		slideInfo := CacheSlideInfo4{}
		if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &slideInfo); err != nil {
			return err
		}
		cache.slideInfo = slideInfo
	default:
		log.Fatalf("got unexpected dyld slide info version: %d", slideInfoVersion)
	}

	file.Seek(int64(cache.header.LocalSymbolsOffset), os.SEEK_SET)
	lsInfo := CacheLocalSymbolsInfo{}
	if err := binary.Read(bufio.NewReader(file), binary.LittleEndian, &lsInfo); err != nil {
		return err
	}
	cache.localSymInfo = lsInfo

	if verbose {

		nlistFileOffset := uint32(cache.header.LocalSymbolsOffset) + cache.localSymInfo.NlistOffset
		// nlistCount := cache.localSymInfo.NlistCount
		// nlistByteSize = is64 ? nlistCount*16 : nlistCount*12;
		nlistByteSize := cache.localSymInfo.NlistCount * 16
		stringsFileOffset := uint32(cache.header.LocalSymbolsOffset) + cache.localSymInfo.StringsOffset
		stringsSize := cache.localSymInfo.StringsSize
		entriesCount := cache.localSymInfo.EntriesCount
		fmt.Printf("local symbols nlist array:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", nlistByteSize/(1024*1024), nlistFileOffset, nlistFileOffset+nlistByteSize)
		fmt.Printf("local symbols string pool:  %3dMB,  file offset: 0x%08X -> 0x%08X\n", stringsSize/(1024*1024), stringsFileOffset, stringsFileOffset+stringsSize)
		fmt.Printf("local symbols by dylib (count=%d):\n", entriesCount)

		file.Seek(int64(uint32(cache.header.LocalSymbolsOffset)+cache.localSymInfo.EntriesOffset), os.SEEK_SET)
		lsr := bufio.NewReader(file)

		var entries []CacheLocalSymbolsEntry
		for i := 0; i < int(entriesCount); i++ {
			entry := CacheLocalSymbolsEntry{}
			if err := binary.Read(lsr, binary.LittleEndian, &entry); err != nil {
				return err
			}
			entries = append(entries, entry)
			fmt.Printf("   nlistStartIndex=%5d, nlistCount=%5d, image=%s\n", entry.NlistStartIndex, entry.NlistCount, cache.images[i].Name)
		}
		if false {
			stringPool := io.NewSectionReader(file, int64(stringsFileOffset), int64(stringsSize))

			file.Seek(int64(nlistFileOffset), os.SEEK_SET)
			nlr := bufio.NewReader(file)

			for idx, entry := range entries {
				for e := 0; e < int(entry.NlistCount); e++ {
					nlist := nlist64{}
					if err := binary.Read(nlr, binary.LittleEndian, &nlist); err != nil {
						return err
					}

					stringPool.Seek(int64(nlist.Strx), os.SEEK_SET)
					s, err := bufio.NewReader(stringPool).ReadString('\x00')
					if err != nil {
						log.Error(errors.Wrapf(err, "failed to read string at: %d", stringsFileOffset+nlist.Strx).Error())
					}

					fmt.Printf("%s,value=0x%016X %s\n", cache.images[idx].Name, nlist.Value, strings.Trim(s, "\x00"))
				}
			}
		}

		if false {
			for idx, entry := range entries {
				file.Seek(int64(entry.DylibOffset), os.SEEK_SET)
				fmt.Printf("%s @ 0x%08X\n", cache.images[idx].Name, entry.DylibOffset)
				if strings.Contains(cache.images[idx].Name, "JavaScriptCore") {
					// if strings.Contains(cache.images[idx].Name, "Foundation") {
					m, err := macho.NewFile(io.NewSectionReader(file, int64(entry.DylibOffset), 1<<63-1))
					if err != nil {
						log.Error(errors.Wrap(err, "failed to parse macho").Error())
					}
					fmt.Println(m)
					m.Sections.Print()
					break
				}
			}
			// file.Seek(int64(image.Info.Address-cache.mappings[0].Address), os.SEEK_SET)

			// // if strings.Contains(cache.images[idx].Name, "JavaScriptCore") {
			// fmt.Printf("%s @ 0x%08X\n", cache.images[idx].Name, int64(image.Info.Address-cache.mappings[0].Address))
			// sr := io.NewSectionReader(file, int64(image.Info.Address-cache.mappings[0].Address), 1<<63-1)
			// mcho, err := macho.NewFile(sr)
			// if err != nil {
			// 	continue
			// 	// return errors.Wrap(err, "failed to create macho")
			// }

			// for _, sec := range mcho.Sections {
			// 	if strings.EqualFold("__cstring", sec.Name) {
			// 		fmt.Printf("%s %s\n", sec.Seg, sec.Name)
			// 		// csr := bufio.NewReader(sec.Open())
			// 		data := make([]byte, sec.Size)
			// 		// data, err := sec.Data()
			// 		// if err != nil {
			// 		// 	log.Fatal(err.Error())
			// 		// }
			// 		file.ReadAt(data, int64(sec.Offset))
			// 		csr := bytes.NewBuffer(data[:])

			// 		for {
			// 			s, err := csr.ReadString('\x00')

			// 			if err == io.EOF {
			// 				break
			// 			}

			// 			if err != nil {
			// 				log.Fatal(err.Error())
			// 			}

			// 			if len(s) > 0 {
			// 				fmt.Printf("%s: %#v\n", cache.images[idx].Name, strings.Trim(s, "\x00"))
			// 			}
			// 		}
			// 	}
			// }
		}
	}

	cache.header.Print()
	cache.mappings.Print()
	// cache.images.Print()

	return nil
}
