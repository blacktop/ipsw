package car

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/car/internal/compression"
	"github.com/blacktop/ipsw/pkg/car/internal/pixel"
)

var errUnsupportedRendition = errors.New("unsupported rendition")

// VariantQuery combines name patterns with exact rendition-key attributes.
// Names matches either the stored rendition name or its logical FACETKEYS name.
// Patterns use path.Match syntax; an empty list matches every name. Numeric
// predicates require the attribute to exist; zero is an exact value, not a wildcard.
// Scale uses the key's scale (1, 2, 3), not the CSI header's percentage scale.
type VariantQuery struct {
	Names        []string
	Scale        *uint16
	Idiom        *uint16
	Appearance   *uint16
	Localization *uint16
	DisplayGamut *uint16
}

// OpaqueBlock retains the uninterpreted bytes of a named BOM block. For a tree,
// Data is its root block; referenced child blocks are still in the original CAR.
type OpaqueBlock struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type CatalogDiagnostic struct {
	Block   string `json:"block"`
	Message string `json:"message"`
}

// CatalogStats separates the complete inventory, selected entries, decoding
// work, and failures. A dependency may be decoded without being selected.
type CatalogStats struct {
	Total            int `json:"total"`
	Selected         int `json:"selected"`
	Deferred         int `json:"deferred"`
	SelectedDeferred int `json:"selected_deferred"`
	DecodeFailures   int `json:"decode_failures"`
	ResolveFailures  int `json:"resolve_failures"`
	ExportFailures   int `json:"export_failures"`
	Exported         int `json:"exported"`
}

func (a *Asset) Stats() CatalogStats {
	s := CatalogStats{Total: len(a.ImageDB)}
	for i, r := range a.ImageDB {
		selected := a.isSelected(i)
		if selected {
			s.Selected++
		}
		if r.Deferred {
			s.Deferred++
			if selected {
				s.SelectedDeferred++
			}
		}
		if r.DecodeError != nil && !errors.Is(r.DecodeError, errUnsupportedRendition) {
			s.DecodeFailures++
		}
		if r.ResolveError != nil && !errors.Is(r.ResolveError, errUnsupportedRendition) {
			s.ResolveFailures++
		}
		if r.ExportError != nil {
			s.ExportFailures++
		}
		if r.ExportPath != "" {
			s.Exported++
		}
	}
	return s
}

func (q *VariantQuery) matches(r *Rendition, logicalName string) bool {
	if q == nil {
		return true
	}
	if len(q.Names) > 0 {
		matched := false
		for _, pattern := range q.Names {
			stored, _ := path.Match(pattern, r.RenditionName)
			logical, _ := path.Match(pattern, logicalName)
			if stored || (logicalName != "" && logical) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, predicate := range []struct {
		attribute renditionAttributeType
		value     *uint16
	}{
		{Scale, q.Scale}, {Idiom, q.Idiom}, {ThemeAppearance, q.Appearance},
		{Localization, q.Localization}, {DisplayGamut, q.DisplayGamut},
	} {
		if predicate.value == nil {
			continue
		}
		value, exists := r.Attributes[predicate.attribute.String()]
		if !exists || value != *predicate.value {
			return false
		}
	}
	return true
}

func (a *Asset) selectRenditions(index renditionIndex) error {
	var query *VariantQuery
	if a.conf != nil {
		query = a.conf.Query
	}
	if query != nil {
		for _, pattern := range query.Names {
			if _, err := path.Match(pattern, ""); err != nil {
				return fmt.Errorf("invalid rendition name pattern %q: %w", pattern, err)
			}
		}
	}
	if err := index.validate(a); err != nil {
		return err
	}
	logicalNames := make(map[uint16][]string)
	if query != nil && len(query.Names) > 0 {
		for name, facet := range a.FacetKeyDB {
			for _, attr := range facet.Attributes {
				if renditionAttributeType(attr.Name) == Identifier {
					logicalNames[attr.Value] = append(logicalNames[attr.Value], name)
				}
			}
		}
	}
	for i := range a.ImageDB {
		r := &a.ImageDB[i]
		r.Selected = query.matches(r, "")
		if !r.Selected {
			for _, name := range logicalNames[r.ID()] {
				if query.matches(r, name) {
					r.Selected = true
					break
				}
			}
		}
	}
	a.selectionReady = true
	return nil
}

// Manually constructed Assets retain the historical all-renditions behavior.
func (a *Asset) isSelected(index int) bool {
	return !a.selectionReady || a.ImageDB[index].Selected
}

func (a *Asset) ensureDecoded(index int) error {
	r := &a.ImageDB[index]
	if !r.Deferred {
		return r.DecodeError
	}
	r.Deferred = false
	r.DecodeError = a.decodeRendition(r, r.header, r.payload)
	if errors.Is(r.DecodeError, errUnsupportedRendition) {
		log.WithField("rendition", r.RenditionName).Warn(r.DecodeError.Error())
	} else if r.DecodeError != nil {
		log.WithField("rendition", r.RenditionName).Errorf("decode: %v", r.DecodeError)
	}
	return r.DecodeError
}

func (r *Rendition) inspectPayload() {
	for _, resource := range r.Resources {
		if resource.ID == MetaDataEXIFOrientationID && len(resource.Data) == 4 {
			r.Orientation = binary.LittleEndian.Uint32(resource.Data)
		}
	}
	if len(r.payload) >= 12 && string(r.payload[:4]) == "MLEC" {
		r.Compression = compressionType(binary.LittleEndian.Uint32(r.payload[8:12])).String()
	}
	switch r.PixelFormat {
	case PixFmtARGB, PixFmtARGB16, PixFmtRGB555, PixFmtGray, PixFmtGray16, PixFmtGrayscale:
		if r.header.Metadata.Layout != InternalLink {
			r.Type = fmt.Sprintf("Image (%s)", r.header.Metadata.Layout)
		}
	case PixFmtPDF, PixFmtJPEG, PixFmtHEIF, PixFmtSVG, PixFmtWebP, PixFmtRawData:
		r.Type = strings.TrimSpace(r.PixelFormat)
	}
}

func (a *Asset) retainBlock(bm *bom.BOM, name, message string) error {
	reader, err := bm.ReadBlock(name)
	if err != nil {
		return fmt.Errorf("read optional block %q: %w", name, err)
	}
	data, err := compression.ReadLimited(reader, pixel.MaxBytes-a.retainedBlockBytes)
	if err != nil {
		return fmt.Errorf("read optional block %q: %w", name, err)
	}
	a.retainedBlockBytes += len(data)
	a.UnknownBlocks = append(a.UnknownBlocks, OpaqueBlock{Name: name, Data: data})
	a.Diagnostics = append(a.Diagnostics, CatalogDiagnostic{Block: name, Message: message})
	return nil
}

// Validate the BOM directory before bom.New allocates from its counts. Optional
// blocks may be unfamiliar, but all directories and block extents must fit the
// input. This also prevents silently retaining a truncated unknown block.
func validateCatalogBOM(r io.ReaderAt, size int64) error {
	var header struct {
		Magic                                                             [8]byte
		Version, Blocks, IndexOffset, IndexLength, VarsOffset, VarsLength uint32
	}
	if err := binary.Read(io.NewSectionReader(r, 0, 32), binary.BigEndian, &header); err != nil {
		return err
	}
	if string(header.Magic[:]) != "BOMStore" {
		return bom.ErrInvalidFormat
	}
	within := func(offset, length uint32) bool {
		return uint64(offset)+uint64(length) <= uint64(size)
	}
	if header.IndexLength < 4 || header.VarsLength < 4 || !within(header.IndexOffset, header.IndexLength) || !within(header.VarsOffset, header.VarsLength) {
		return fmt.Errorf("BOM directory exceeds file")
	}
	const maxDirectoryBytes = 16 << 20
	if header.IndexLength > maxDirectoryBytes || header.VarsLength > maxDirectoryBytes {
		return fmt.Errorf("BOM directory exceeds size limit")
	}
	index := io.NewSectionReader(r, int64(header.IndexOffset), int64(header.IndexLength))
	var count uint32
	if err := binary.Read(index, binary.BigEndian, &count); err != nil {
		return err
	}
	if uint64(count)*8+4 > uint64(header.IndexLength) {
		return fmt.Errorf("BOM pointer count exceeds index")
	}
	for range count {
		var pointer bom.Pointer
		if err := binary.Read(index, binary.BigEndian, &pointer); err != nil {
			return err
		}
		if !within(pointer.Address, pointer.Length) {
			return fmt.Errorf("BOM block exceeds file")
		}
	}
	vars := io.NewSectionReader(r, int64(header.VarsOffset), int64(header.VarsLength))
	var varCount uint32
	if err := binary.Read(vars, binary.BigEndian, &varCount); err != nil {
		return err
	}
	if uint64(varCount)*5+4 > uint64(header.VarsLength) {
		return fmt.Errorf("BOM variable count exceeds directory")
	}
	names := make(map[string]bool)
	for range varCount {
		var index uint32
		var length uint8
		if err := binary.Read(vars, binary.BigEndian, &index); err != nil {
			return err
		}
		if index >= count {
			return fmt.Errorf("BOM variable refers to missing block")
		}
		if err := binary.Read(vars, binary.BigEndian, &length); err != nil {
			return err
		}
		name := make([]byte, length)
		if _, err := io.ReadFull(vars, name); err != nil {
			return err
		}
		key := string(bytes.Trim(name, "\x00"))
		if names[key] {
			return fmt.Errorf("duplicate BOM variable %q", key)
		}
		names[key] = true
	}
	return nil
}
