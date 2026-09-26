package car

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/car/internal/compression"
)

func unsupportedDrawingLayout(layout renditionLayoutType) bool {
	return layout == Effect || layout == Gradient || layout == NamedGradient
}

func exportExtension(rend *Rendition) string {
	if unsupportedDrawingLayout(rend.header.Metadata.Layout) {
		return ""
	}
	if _, ok := rend.Asset.(image.Image); ok {
		return ".png"
	}
	if rend.Compression == HEVC.String() {
		return ".heic"
	}
	switch rend.Asset.(type) {
	case csiColor, csiMultisizeImageSet:
		return ".json"
	}
	switch rend.PixelFormat {
	case PixFmtARGB, PixFmtARGB16, PixFmtRGB555, PixFmtGray, PixFmtGray16, PixFmtGrayscale:
		return ".png"
	case PixFmtPDF:
		return ".pdf"
	case PixFmtJPEG:
		return ".jpg"
	case PixFmtHEIF:
		return ".heic"
	case PixFmtSVG:
		return ".svg"
	case PixFmtWebP:
		return ".webp"
	case PixFmtRawData:
		return ".raw"
	}
	switch rend.header.Metadata.Layout {
	case Color, MultiSizeImageSet:
		return ".json"
	case InternalLink:
		return ".png"
	}
	return ""
}

// ExportCrop describes a reference frame in CoreUI's bottom-left coordinates.
// Crops are ordered from the final rendition toward its source atlas.
type ExportCrop struct {
	X      uint32 `json:"x"`
	Y      uint32 `json:"y"`
	Width  uint32 `json:"width"`
	Height uint32 `json:"height"`
}

// ExportEntry describes a destination and its observed state. A planned entry
// has not necessarily been decoded; Deferred makes that distinction explicit.
type ExportEntry struct {
	Key         []uint16     `json:"key"`
	Name        string       `json:"name"`
	Path        string       `json:"path,omitempty"`
	Format      string       `json:"format,omitempty"`
	ColorSpace  string       `json:"color_space,omitempty"`
	Orientation uint32       `json:"orientation,omitempty"`
	Compression string       `json:"compression,omitempty"`
	Width       uint32       `json:"width,omitempty"`
	Height      uint32       `json:"height,omitempty"`
	SourceKey   []uint16     `json:"source_key,omitempty"`
	Crops       []ExportCrop `json:"crops,omitempty"`
	Deferred    bool         `json:"deferred"`
	Status      string       `json:"status"`
	Error       string       `json:"error,omitempty"`
	Warnings    []string     `json:"warnings,omitempty"`
	index       int
}

// PlanExport computes deterministic destinations without decoding or writing.
// It includes every selected rendition, including failed and unknown formats.
func (a *Asset) PlanExport(output string) []ExportEntry {
	order := make([]int, 0, len(a.ImageDB))
	byKey := make(map[string]int, len(a.ImageDB))
	for i := range a.ImageDB {
		byKey[renditionKey(a.ImageDB[i].Key)] = i
		if a.isSelected(i) {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		return renditionKey(a.ImageDB[order[i]].Key) < renditionKey(a.ImageDB[order[j]].Key)
	})
	entries := make([]ExportEntry, 0, len(order))
	used := make(map[string]bool)
	for _, i := range order {
		rend := &a.ImageDB[i]
		entry := ExportEntry{index: i, Key: append([]uint16(nil), rend.Key...), Name: rend.RenditionName,
			Compression: rend.Compression, Width: rend.Width, Height: rend.Height, Deferred: rend.Deferred,
			ColorSpace: rend.Colorspace, Orientation: rend.Orientation,
			Status: "planned", Warnings: append([]string(nil), rend.Warnings...)}
		raw := a.conf != nil && a.conf.Raw
		failures := []error{rend.ExportError}
		if !raw {
			for _, err := range []error{rend.DecodeError, rend.ResolveError} {
				if errors.Is(err, errUnsupportedRendition) {
					entry.Status, entry.Error = "unsupported", err.Error()
				} else {
					failures = append(failures, err)
				}
			}
		}
		for _, err := range failures {
			if err != nil {
				entry.Status, entry.Error = "failed", err.Error()
				break
			}
		}
		ext := exportExtension(rend)
		if a.conf != nil && a.conf.Raw {
			ext = ".csi"
		} else {
			format, known := plannedSourceFormat(rend)
			if a.conf != nil && a.conf.Render {
				if isRenderableFormat(format) {
					ext = ".png"
					entry.ColorSpace = SRGB.String()
				} else if !known && rend.Deferred {
					entry.ColorSpace = ""
					entry.Warnings = append(entry.Warnings, "Rendering may change the destination to PNG after the DATA payload is decoded")
				}
			}
			if rend.link != nil {
				ext = ".png"
				if rend.isRawLink() {
					ext = ".raw"
				}
			}
			if err := a.planReference(i, byKey, &entry); err != nil && entry.Error == "" {
				entry.Status, entry.Error = "failed", err.Error()
				if errors.Is(err, errUnsupportedRendition) {
					entry.Status = "unsupported"
				}
			}
		}
		if img, ok := rend.Asset.(image.Image); ok {
			entry.Width, entry.Height = uint32(img.Bounds().Dx()), uint32(img.Bounds().Dy())
		}
		if a.conf != nil && a.conf.ApplyOrientation && ext == ".png" {
			for _, resource := range rend.Resources {
				if resource.ID == MetaDataEXIFOrientationID && len(resource.Data) != 4 {
					entry.Status, entry.Error = "failed", "EXIF orientation resource must contain four bytes"
				}
			}
			if rend.Orientation > 8 {
				entry.Status, entry.Error = "failed", fmt.Sprintf("invalid EXIF orientation: %d", rend.Orientation)
			}
			if rend.Orientation >= 5 && rend.Orientation <= 8 {
				entry.Width, entry.Height = entry.Height, entry.Width
			}
		}
		if ext == "" {
			if entry.Error == "" {
				entry.Status, entry.Error = "unsupported", "no export format for this rendition"
			}
		} else {
			base := rend.RenditionName
			if rend.PixelFormat == PixFmtRawData || rend.isRawLink() {
				if name := a.GetName(rend.ID()); name != "" {
					base = strings.TrimRight(name, "\x00")
				}
			}
			base = safeExportStem(base)
			if ext == ".raw" {
				if originalExt := filepath.Ext(base); len(originalExt) > 1 && len(originalExt) <= 16 {
					ext = originalExt
				}
			}
			if strings.HasSuffix(strings.ToLower(base), strings.ToLower(ext)) {
				base = base[:len(base)-len(ext)]
			}
			digest := sha256.Sum256([]byte(renditionKey(rend.Key)))
			name := fmt.Sprintf("%s-%x%s", base, digest[:8], ext)
			for suffix := 1; used[strings.ToLower(name)]; suffix++ {
				name = fmt.Sprintf("%s-%x-%d%s", base, digest[:8], suffix, ext)
			}
			used[strings.ToLower(name)] = true
			entry.Path, entry.Format = filepath.Join(output, name), strings.TrimPrefix(ext, ".")
			if rend.ExportPath != "" {
				entry.Status = "exported"
				entry.Path = rend.ExportPath
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

func (a *Asset) planReference(index int, byKey map[string]int, entry *ExportEntry) error {
	seen := make(map[int]bool)
	raw := a.ImageDB[index].isRawLink()
	for depth := 0; ; depth++ {
		rend := &a.ImageDB[index]
		if rend.link == nil {
			if depth > 0 {
				entry.SourceKey = append([]uint16(nil), rend.Key...)
				entry.ColorSpace = rend.ColorSpace.String()
				if raw {
					if len(rend.rawCSI) != 0 {
						entry.ColorSpace = rend.header.ColorSpace.ColorSpaceID().String()
					}
					if rend.PixelFormat != PixFmtRawData {
						return fmt.Errorf("%w: raw link target is %q", errUnsupportedRendition, rend.PixelFormat)
					}
				} else if _, decoded := rend.Asset.(image.Image); !decoded {
					if format, known := plannedSourceFormat(rend); isRenderableFormat(format) {
						entry.ColorSpace = SRGB.String()
					} else if !known {
						entry.ColorSpace = ""
						entry.Warnings = append(entry.Warnings, "Reference output color space depends on the deferred DATA source format")
					}
				}
				for _, warning := range rend.Warnings {
					if !slices.Contains(entry.Warnings, warning) {
						entry.Warnings = append(entry.Warnings, warning)
					}
				}
			}
			return nil
		}
		if depth >= maxReferenceDepth || seen[index] {
			return fmt.Errorf("reference cycle or depth limit in export plan")
		}
		seen[index] = true
		if raw != rend.isRawLink() {
			return fmt.Errorf("%w: mixed raw and image reference chain", errUnsupportedRendition)
		}
		frame := rend.link.Frame
		if !raw {
			entry.Crops = append(entry.Crops, ExportCrop(frame))
			if depth == 0 {
				entry.Width, entry.Height = frame.Width, frame.Height
			}
		}
		key, err := referenceKey(rend.link, a.KeyFormat)
		if err != nil {
			return err
		}
		next, ok := byKey[key]
		if !ok {
			return fmt.Errorf("reference target not found for key %x", key)
		}
		target := &a.ImageDB[next]
		w, h := target.Width, target.Height
		if target.link != nil {
			w, h = target.link.Frame.Width, target.link.Frame.Height
		}
		if !raw && (frame.Width == 0 || frame.Height == 0 ||
			(w > 0 && uint64(frame.X)+uint64(frame.Width) > uint64(w)) ||
			(h > 0 && uint64(frame.Y)+uint64(frame.Height) > uint64(h))) {
			return fmt.Errorf("reference crop exceeds target dimensions")
		}
		index = next
	}
}

// plannedSourceFormat inspects available source headers without decompressing.
// A compressed DATA payload may reveal its source format only during decoding.
func plannedSourceFormat(rend *Rendition) (string, bool) {
	if rend.Compression == HEVC.String() {
		return PixFmtHEIF, true
	}
	if rend.PixelFormat != PixFmtRawData {
		return rend.PixelFormat, true
	}
	data, ok := rend.Asset.([]byte)
	if !ok {
		data = rend.payload
		if len(data) >= 12 && string(data[:4]) == "DWAR" && uint64(binary.LittleEndian.Uint32(data[8:])) == uint64(len(data)-12) {
			data = data[12:]
		} else if len(data) >= 16 && string(data[:4]) == "MLEC" {
			elem, chunks, err := readCSIBitmap(data)
			if err != nil || elem.Encoding != Uncompressed || len(chunks) != 1 {
				return PixFmtRawData, false
			}
			data = chunks[0].data
		}
		if compression.IsAppleStream(data) {
			return PixFmtRawData, false
		}
	}
	return renderedPayloadFormat(data, PixFmtRawData), true
}

// WriteManifest records selected export destinations, results and full-catalog
// counts. Callers choose the writer; this method does not create any files.
func (a *Asset) WriteManifest(w io.Writer, output string) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		Version     int                 `json:"version"`
		Catalog     CatalogStats        `json:"catalog"`
		Entries     []ExportEntry       `json:"entries"`
		Diagnostics []CatalogDiagnostic `json:"diagnostics,omitempty"`
	}{1, a.Stats(), a.PlanExport(output), a.Diagnostics})
}

func safeExportStem(name string) string {
	var stem strings.Builder
	for _, r := range strings.TrimSpace(name) {
		if stem.Len() >= 150 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.', r == '@':
			stem.WriteRune(r)
		default:
			stem.WriteByte('_')
		}
	}
	cleaned := strings.Trim(stem.String(), ". ")
	if cleaned == "" {
		return "asset"
	}
	return cleaned
}

func (a *Asset) exportRenditions() {
	if a.conf == nil || !a.conf.Export || a.conf.Output == "" || a.conf.MetadataOnly {
		return
	}
	for i := range a.ImageDB {
		if a.isSelected(i) {
			a.ImageDB[i].ExportError = nil
			a.ImageDB[i].ExportPath = ""
		}
	}
	plan := a.PlanExport(a.conf.Output)
	if len(plan) == 0 {
		return
	}
	directoryErr := os.MkdirAll(a.conf.Output, 0o755)
	for _, entry := range plan {
		if entry.Status == "unsupported" {
			continue
		}
		rend := &a.ImageDB[entry.index]
		if !a.conf.Raw && (rend.DecodeError != nil || rend.ResolveError != nil) {
			continue
		}
		err := directoryErr
		if entry.Error != "" {
			err = fmt.Errorf("%s", entry.Error)
		}
		var value any = rend.Asset
		if a.conf.Raw {
			value = rend.rawCSI
		}
		if err == nil && a.conf.ApplyOrientation && !a.conf.Raw {
			if img, ok := value.(image.Image); ok {
				value, err = orientImage(img, rend.Orientation)
			}
		}
		if err == nil {
			err = writeRendition(entry.Path, value, rend.ColorSpace)
		}
		if err != nil {
			rend.ExportError = err
			log.WithField("rendition", rend.RenditionName).Errorf("export: %v", err)
		} else {
			rend.ExportPath = entry.Path
		}
	}
}

func writeRendition(path string, asset any, space colorSpaceID) error {
	// Replace the directory entry only after a successful write. Existing
	// symlinks are replaced, never followed, and failures preserve old output.
	temp := filepath.Join(filepath.Dir(path), ".car-"+rand.Text())
	f, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	// New files use 0644 subject to umask. Preserve an existing regular file's
	// mode without consulting a symlink's target.
	if info, statErr := os.Lstat(path); statErr == nil && info.Mode().IsRegular() {
		err = f.Chmod(info.Mode().Perm())
	} else if statErr != nil && !os.IsNotExist(statErr) {
		err = statErr
	}
	if err == nil {
		switch value := asset.(type) {
		case image.Image:
			err = encodePNG(f, value, space)
		case []byte:
			_, err = f.Write(value)
		case csiColor, csiMultisizeImageSet:
			encoder := json.NewEncoder(f)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(value)
		default:
			err = fmt.Errorf("unsupported export asset: %T", asset)
		}
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
