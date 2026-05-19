package kalloctype

import (
	"errors"
	"fmt"

	"github.com/blacktop/go-macho"
	mtypes "github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
)

const (
	sectionSegment = "__DATA_CONST"
	fixedSection   = "__kalloc_type"
	varSection     = "__kalloc_var"

	zoneViewNameOffset = uint64(0x10)

	fixedViewSize        = uint64(0x40)
	fixedSignatureOffset = uint64(0x20)
	fixedFlagsOffset     = 0x28
	fixedSizeOffset      = 0x2c

	varViewSize            = uint64(0x50)
	varSizeTypeOffset      = 0x04
	varNameOffset          = uint64(0x10)
	varHdrSignatureOffset  = uint64(0x38)
	varElemSignatureOffset = uint64(0x40)
	varFlagsOffset         = 0x48
)

var ErrNoKallocTypeSection = errors.New("no __DATA_CONST.__kalloc_type section")

func Scan(root *macho.File) ([]Record, error) {
	if root == nil {
		return nil, fmt.Errorf("nil kernelcache")
	}

	kernel := kernelFile(root)
	scanner := cpp.NewScanner(root, cpp.Config{})

	records, err := scanFixedViews(scanner, kernel)
	if err != nil {
		return nil, err
	}
	varRecords, err := scanVarViews(scanner, kernel)
	if err != nil {
		return nil, err
	}
	records = append(records, varRecords...)
	SortRecords(records)
	return records, nil
}

func kernelFile(root *macho.File) *macho.File {
	if root.Type != mtypes.MH_FILESET {
		return root
	}
	if kernel, err := root.GetFileSetFileByName("com.apple.kernel"); err == nil {
		return kernel
	}
	return root
}

func scanFixedViews(scanner *cpp.Scanner, kernel *macho.File) ([]Record, error) {
	sec := kernel.Section(sectionSegment, fixedSection)
	if sec == nil {
		return nil, ErrNoKallocTypeSection
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read %s.%s: %w", sectionSegment, fixedSection, err)
	}
	if sec.Size%fixedViewSize != 0 {
		return nil, fmt.Errorf("%s.%s size %#x is not a multiple of kalloc_type_view size %#x", sectionSegment, fixedSection, sec.Size, fixedViewSize)
	}
	if uint64(len(data)) < sec.Size {
		return nil, fmt.Errorf("%s.%s data truncated: got %#x bytes, section size %#x", sectionSegment, fixedSection, len(data), sec.Size)
	}

	count := int(sec.Size / fixedViewSize)
	records := make([]Record, 0, count)
	for idx := range count {
		entryOffset := idx * int(fixedViewSize)
		site := sec.Addr + uint64(entryOffset)
		flags := kernel.ByteOrder.Uint32(data[entryOffset+fixedFlagsOffset:])
		size := kernel.ByteOrder.Uint32(data[entryOffset+fixedSizeOffset:])
		name := readCStringPointer(scanner, kernel, site+zoneViewNameOffset)
		signature := readSignaturePointer(scanner, kernel, site+fixedSignatureOffset)
		records = append(records, Record{
			Kind:         KindFixed,
			Name:         name,
			Signature:    signature,
			Size:         size,
			Flags:        flags,
			FlagsDecoded: DecodeFlags(flags),
			Site:         site,
		})
	}
	return records, nil
}

func scanVarViews(scanner *cpp.Scanner, kernel *macho.File) ([]Record, error) {
	sec := kernel.Section(sectionSegment, varSection)
	if sec == nil || sec.Size == 0 {
		return nil, nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read %s.%s: %w", sectionSegment, varSection, err)
	}
	if sec.Size%varViewSize != 0 {
		return nil, fmt.Errorf("%s.%s size %#x is not a multiple of kalloc_type_var_view size %#x", sectionSegment, varSection, sec.Size, varViewSize)
	}
	if uint64(len(data)) < sec.Size {
		return nil, fmt.Errorf("%s.%s data truncated: got %#x bytes, section size %#x", sectionSegment, varSection, len(data), sec.Size)
	}

	count := int(sec.Size / varViewSize)
	records := make([]Record, 0, count)
	for idx := range count {
		entryOffset := idx * int(varViewSize)
		site := sec.Addr + uint64(entryOffset)
		flags := kernel.ByteOrder.Uint32(data[entryOffset+varFlagsOffset:])
		size := kernel.ByteOrder.Uint32(data[entryOffset+varSizeTypeOffset:])
		name := readCStringPointer(scanner, kernel, site+varNameOffset)
		hdrSignature := readSignaturePointer(scanner, kernel, site+varHdrSignatureOffset)
		elemSignature := readSignaturePointer(scanner, kernel, site+varElemSignatureOffset)
		records = append(records, Record{
			Kind:          KindVar,
			Name:          name,
			Signature:     elemSignature,
			Size:          size,
			Flags:         flags,
			FlagsDecoded:  DecodeFlags(flags),
			Site:          site,
			HdrSignature:  hdrSignature,
			ElemSignature: elemSignature,
		})
	}
	return records, nil
}

func readCStringPointer(scanner *cpp.Scanner, owner *macho.File, ptrAddr uint64) string {
	ptr, ok := scanner.ReadPointerAt(owner, ptrAddr)
	if !ok || ptr == 0 {
		return ""
	}
	value, err := scanner.ReadCStringAt(owner, ptr)
	if err != nil {
		return ""
	}
	return value
}

func readSignaturePointer(scanner *cpp.Scanner, owner *macho.File, ptrAddr uint64) string {
	signature := readCStringPointer(scanner, owner, ptrAddr)
	if !isKallocSignature(signature) {
		return ""
	}
	return signature
}

func isKallocSignature(signature string) bool {
	for _, r := range signature {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
