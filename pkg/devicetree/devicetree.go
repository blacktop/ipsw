package devicetree

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"fmt"
	"io"
	"math"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img3"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/lzfse"
)

// Img4 DeviceTree object
type Img4 struct {
	IM4P     string
	Name     string
	Version  string
	Data     []byte
	KbagData []byte `asn1:"optional"`
}

// Node object
type Node struct {
	NumProperties uint32 // Number of props[] elements (0 => end)
	NumChildren   uint32 // Number of children[] elements
}

// NodeProperty object
type NodeProperty struct {
	Name   [32]byte // NUL terminated property name (max length 32)
	Length uint32   // Length (bytes) of folloing prop value
}

// Properties object
type Properties map[string]any

// DeviceTree object
type DeviceTree map[string]Properties

type dtCPU struct {
	Name string
	Type string
	ARM  string
}

// Summary object
type Summary struct {
	ProductName        string
	ProductDescription string
	ProductType        string
	BoardConfig        string
	SocName            string
	DeviceType         string
	SocGeneration      string
	CPUs               []dtCPU
	Timestamp          time.Time
}

// Summary prints out a summary of the DeviceTree
func (dtree *DeviceTree) Summary() (*Summary, error) {
	summary := &Summary{}

	children := (*dtree)["device-tree"]["children"]

	if children == nil {
		return nil, fmt.Errorf("failed to get device tree node children")
	}

	switch reflect.TypeOf(children).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(children)
		for i := range s.Len() {
			child := s.Index(i)
			c := child.Interface().(DeviceTree)
			if product, ok := (c)["product"]["product-name"].(string); ok {
				summary.ProductName = product
			}
			if productDesc, ok := (c)["product"]["product-description"].(string); ok {
				summary.ProductDescription = productDesc
			}
			if socName, ok := (c)["product"]["product-soc-name"].(string); ok {
				summary.SocName = socName
			}
			if devType, ok := (c)["arm-io"]["compatible"].(string); ok {
				summary.DeviceType = strings.TrimPrefix(devType, "arm-io,")
			}
			if socGeneration, ok := (c)["arm-io"]["soc-generation"].(string); ok {
				summary.SocGeneration = socGeneration
			}
			if cpus, ok := (c)["cpus"]["children"]; ok {
				for idx, cpu := range cpus.([]DeviceTree) {
					if cpuN, ok := cpu[fmt.Sprintf("cpu%d", idx)]; ok {
						if compat, ok := cpuN["compatible"].([]string); ok {
							c := dtCPU{}
							if len(compat) == 2 {
								c.Name = strings.TrimPrefix(compat[0], "apple,")
								c.ARM = strings.TrimPrefix(compat[1], "ARM,")
							}
							if clusterType, ok := cpuN["cluster-type"].(string); ok {
								c.Type = clusterType
							}
							summary.CPUs = append(summary.CPUs, c)
						}
					}
				}
			}
		}
	}

	if model, ok := (*dtree)["device-tree"]["model"].(string); ok {
		summary.ProductType = model
		summary.BoardConfig = boardConfig((*dtree)["device-tree"]["compatible"], model)
	} else {
		return nil, fmt.Errorf("devicetree model is not a string")
	}

	if stamp, ok := (*dtree)["device-tree"]["time-stamp"].(string); ok {
		layout := "Mon Jan 2 15:04:05 MST 2006"
		if location, err := time.LoadLocation("PST8PDT"); err == nil {
			t, err := time.ParseInLocation(layout, stamp, location)
			if err != nil {
				return nil, err
			}
			zone, _ := time.Now().Zone()
			location, err = time.LoadLocation(zone)
			if err != nil {
				// return nil, fmt.Errorf("failed to load location %s: %v", zone, err)
				summary.Timestamp = t
			} else {
				summary.Timestamp = t.In(location)
			}
		} else {
			summary.Timestamp, err = time.Parse(layout, stamp)
			if err != nil {
				return nil, fmt.Errorf("failed to parse device-tree time-stamp: %v", err)
			}
		}
	}

	return summary, nil
}

func printNode(out *strings.Builder, node Properties, depth int) {
	for k, v := range node {
		switch k {
		case "children":
			switch reflect.TypeOf(v).Kind() {
			case reflect.Slice:
				s := reflect.ValueOf(v)
				for i := range s.Len() {
					child := s.Index(i)
					for kk, vv := range child.Interface().(DeviceTree) {
						out.WriteString(fmt.Sprintf("%s%s:\n", strings.Repeat(" ", depth+2), kk))
						printNode(out, vv, depth+4)
					}
				}
			}
		default:
			switch vv := v.(type) {
			case int:
				if vv == 0 || vv < 1000 {
					out.WriteString(fmt.Sprintf("%s%s: %d\n", strings.Repeat(" ", depth), k, vv))
				} else {
					out.WriteString(fmt.Sprintf("%s%s: %#x\n", strings.Repeat(" ", depth), k, vv))
				}
			case uint16:
				if vv == 0 || vv < 1000 {
					out.WriteString(fmt.Sprintf("%s%s: %d\n", strings.Repeat(" ", depth), k, vv))
				} else {
					out.WriteString(fmt.Sprintf("%s%s: %#x\n", strings.Repeat(" ", depth), k, vv))
				}
			case uint32:
				if vv == 0 || vv < 1000 {
					out.WriteString(fmt.Sprintf("%s%s: %d\n", strings.Repeat(" ", depth), k, vv))
				} else {
					out.WriteString(fmt.Sprintf("%s%s: %#x\n", strings.Repeat(" ", depth), k, vv))
				}
			case uint64:
				if vv == 0 || vv < 1000 {
					out.WriteString(fmt.Sprintf("%s%s: %d\n", strings.Repeat(" ", depth), k, vv))
				} else {
					out.WriteString(fmt.Sprintf("%s%s: %#x\n", strings.Repeat(" ", depth), k, vv))
				}
			case string:
				out.WriteString(fmt.Sprintf("%s%s: \"%s\"\n", strings.Repeat(" ", depth), k, vv))
			case []string:
				for _, s := range vv {
					out.WriteString(fmt.Sprintf("%s%s: \"%s\"\n", strings.Repeat(" ", depth+2), k, s))
				}
			case pmgr_dev:
				out.WriteString(fmt.Sprintf("%s%s: \n%s\n", strings.Repeat(" ", depth), k, vv.String(depth+2)))
			case []pmgr_dev:
				for _, dev := range vv {
					out.WriteString(fmt.Sprintf("%s%s: \n%s\n", strings.Repeat(" ", depth), k, dev.String(depth+2)))
				}
			case pmgr_map:
				out.WriteString(fmt.Sprintf("%s%s: reg=%#x off=%#x unk=%#x\n", strings.Repeat(" ", depth), k, vv.Reg, vv.Off, vv.Unk))
			case []pmgr_map:
				for _, m := range vv {
					out.WriteString(fmt.Sprintf("%s%s: reg=%#x off=%#x unk=%#x\n", strings.Repeat(" ", depth), k, m.Reg, m.Off, m.Unk))
				}
			case pmgr_reg:
				out.WriteString(fmt.Sprintf("%s%s: addr=%#x sz=%#x\n", strings.Repeat(" ", depth), k, vv.Addr, vv.Size))
			case []pmgr_reg:
				for _, reg := range vv {
					out.WriteString(fmt.Sprintf("%s%s: addr=%#x sz=%#x\n", strings.Repeat(" ", depth+2), k, reg.Addr, reg.Size))
				}
			case PmapIORange:
				out.WriteString(fmt.Sprintf("%s%s: %#v\n", strings.Repeat(" ", depth), k, vv))
			case []PmapIORange:
				out.WriteString(fmt.Sprintf("%s%s:\n", strings.Repeat(" ", depth), k))
				for _, pmap := range vv {
					out.WriteString(fmt.Sprintf("%s\"%s\" start=%#x sz=%#x flags=%#x\n", strings.Repeat(" ", depth+2), pmap.Name[:], pmap.Start, pmap.Size, pmap.Flags))
				}
			case []region:
				out.WriteString(fmt.Sprintf("%s%s:\n", strings.Repeat(" ", depth), k))
				for _, reg := range vv {
					out.WriteString(fmt.Sprintf("%sstart=%#06x end=%#06x\n", strings.Repeat(" ", depth+2), reg.Start, reg.End))
				}
			default:
				out.WriteString(fmt.Sprintf("%s%s: %v\n", strings.Repeat(" ", depth), k, vv))
			}
		}
	}
}

func (dtree *DeviceTree) String() string {
	var out strings.Builder
	for k, v := range *dtree {
		out.WriteString(fmt.Sprintf("%s:\n", k))
		printNode(&out, v, 2)
	}
	return out.String()
}

// GetProductName returns the device-trees product names
func (dtree *DeviceTree) GetProductName() (string, error) {
	children := (*dtree)["device-tree"]["children"]

	switch reflect.TypeOf(children).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(children)
		for i := range s.Len() {
			child := s.Index(i)
			c := child.Interface().(DeviceTree)
			if product, ok := (c)["product"]["product-name"].(string); ok {
				return product, nil
			}
		}
	}
	return "", fmt.Errorf("failed to get product-name")
}

// GetBoardConfig returns the device-trees board config
func (dtree *DeviceTree) GetBoardConfig() (string, error) {
	if model, ok := (*dtree)["device-tree"]["model"].(string); ok {
		utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", model))
		if board := boardConfig((*dtree)["device-tree"]["compatible"], model); board != "" {
			return board, nil
		}
	}
	return "", fmt.Errorf("failed to get board-config")
}

// boardConfig returns the root compatible entry that is neither the model nor "AppleARM" (e.g. "V63AP").
func boardConfig(compatible any, model string) string {
	list, ok := compatible.([]string)
	if !ok {
		return ""
	}
	for _, elem := range list {
		if elem != "" && !strings.Contains(elem, "Apple") && !strings.Contains(elem, model) {
			return elem
		}
	}
	return ""
}

// GetModel returns the device-trees model
func (dtree *DeviceTree) GetModel() (string, error) {
	if model, ok := (*dtree)["device-tree"]["model"].(string); ok {
		return model, nil
	}
	return "", fmt.Errorf("failed to get model")
}

func isZero(bytes []byte) bool {
	b := byte(0)
	for _, s := range bytes {
		b |= s
	}
	return b == 0
}

func parseInt(value []byte) any {
	switch len(value) {
	case 0:
		return nil
	case 1, 2, 4, 8:
		return parseNumber(value)
	}
	return parseValue(value)
}

// parseNumber decodes 1, 2, 4 and 8 byte little-endian integers; other sizes are returned as Data.
func parseNumber(value []byte) any {
	negative := bytes.HasSuffix(value, []byte("\xff"))
	switch len(value) {
	case 1:
		return uint8(value[0])
	case 2:
		if negative {
			return int16(binary.LittleEndian.Uint16(value))
		}
		return binary.LittleEndian.Uint16(value)
	case 4:
		if negative {
			return int32(binary.LittleEndian.Uint32(value))
		}
		return binary.LittleEndian.Uint32(value)
	case 8:
		if negative {
			return int64(binary.LittleEndian.Uint64(value))
		}
		return binary.LittleEndian.Uint64(value)
	}
	return Data(value)
}

// parseValue decodes a property value without a known format.
// value must be the exact property length (without alignment padding).
func parseValue(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	if isZero(value) {
		return 0
	}
	if str, ok := parseString(value); ok {
		return str
	}
	if list, ok := parseStringList(value); ok {
		return list
	}
	return parseNumber(value)
}

// parseString accepts NUL-terminated text and unterminated printable bytes (e.g. FourCC
// tags). DeviceTree strings carry exactly one NUL; more trailing NULs mean a small
// integer or a fixed-width buffer, which must hold at least 4 characters.
func parseString(value []byte) (string, bool) {
	str := bytes.TrimRight(value, "\x00")
	trailing := len(value) - len(str)
	switch {
	case trailing == 0:
		return string(value), isPrintable(value)
	case len(str) == 0 || !isPrintable(str):
		return "", false
	case trailing == 1:
		return string(str), true
	default:
		return string(str), len(value) > 4 && len(str) >= 4
	}
}

// parseStringList accepts NUL-separated text with no empty entries, so no bytes are dropped.
func parseStringList(value []byte) ([]string, bool) {
	trimmed := bytes.TrimRight(value, "\x00")
	if len(trimmed) == len(value) {
		return nil, false
	}
	parts := bytes.Split(trimmed, []byte("\x00"))
	if len(parts) < 2 {
		return nil, false
	}
	list := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 || !isPrintable(part) {
			return nil, false
		}
		list = append(list, string(part))
	}
	return list, true
}

func parseOffSz(value []byte) any {
	switch {
	case len(value) > 4:
		kind := binary.LittleEndian.Uint32(value[:4])
		_ = kind
		switch len(value[4:]) {
		case binary.Size(uint8(0)):
			return uint8(value[4])
		case binary.Size(uint16(0)):
			return uint16(binary.LittleEndian.Uint16(value[4:]))
		case binary.Size(uint32(0)):
			return uint32(binary.LittleEndian.Uint32(value[4:]))
		case binary.Size(uint64(0)):
			return uint64(binary.LittleEndian.Uint64(value[4:]))
		}
	}
	return parseValue(value)
}

func parseReg(value []byte) any {
	switch len(value) {
	case binary.Size(pmgr_reg{}):
		var reg pmgr_reg
		if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, &reg); err != nil {
			return parseValue(value)
		}
		return reg
	case binary.Size(uint32(0)):
		var reg uint32
		if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, &reg); err != nil {
			return parseValue(value)
		}
		return reg
	default:
		if len(value)%binary.Size(pmgr_reg{}) == 0 {
			regs := make([]pmgr_reg, len(value)/binary.Size(pmgr_reg{}))
			if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, &regs); err != nil {
				return parseValue(value)
			}
			return regs
		}
		return parseValue(value)
	}
}

func parseAddr(value []byte) any {
	if len(value) == binary.Size(uint64(0)) {
		var addr uint64
		if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, &addr); err != nil {
			return parseValue(value)
		}
		return addr
	}
	return parseValue(value)
}

type PmapIORange struct {
	Start uint64
	Size  uint64
	Flags uint32
	Name  [4]byte
}

func (p *PmapIORange) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Start uint64 `json:"start,omitempty"`
		Size  uint64 `json:"size,omitempty"`
		Flags uint32 `json:"flags,omitempty"`
		Name  string `json:"name,omitempty"`
	}{
		Start: p.Start,
		Size:  p.Size,
		Flags: p.Flags,
		Name:  string(p.Name[:]),
	})
}

func parsePmapIORanges(value []byte) any {
	var ranges []PmapIORange
	r := bytes.NewReader(value)
	for {
		var pmap PmapIORange
		err := binary.Read(r, binary.LittleEndian, &pmap)
		if err != nil {
			if err == io.EOF {
				break
			}
			return parseValue(value)
		}
		slices.Reverse(pmap.Name[:])
		ranges = append(ranges, pmap)
	}
	return ranges
}

type region struct {
	Start uint64
	End   uint64
}

func parseRegions(value []byte) any {
	var regions []region
	r := bytes.NewReader(value)
	for {
		var reg region
		err := binary.Read(r, binary.LittleEndian, &reg)
		if err != nil {
			if err == io.EOF {
				break
			}
			return parseValue(value)
		}
		regions = append(regions, reg)
	}
	return regions
}

func parseNode(buffer io.Reader) (Node, error) {
	var node Node
	// Read a Node from the buffer
	if err := binary.Read(buffer, binary.LittleEndian, &node); err != nil {
		return Node{}, err
	}
	return node, nil
}

// rawProperty is a property value as stored, before decoding.
type rawProperty struct {
	key      string
	template bool
	value    []byte
}

func readNodeProperty(buffer io.Reader) (rawProperty, error) {
	var nProp NodeProperty
	if err := binary.Read(buffer, binary.LittleEndian, &nProp); err != nil {
		return rawProperty{}, err
	}
	length := nProp.Length & math.MaxInt32
	// values are padded to a 4 byte boundary; the padding is not part of the value
	dat := make([]byte, (length+3)&^3)
	if _, err := io.ReadFull(buffer, dat); err != nil {
		return rawProperty{}, err
	}
	return rawProperty{
		key:      string(bytes.TrimRight(nProp.Name[:], "\x00")),
		template: nProp.Length&^math.MaxInt32 != 0,
		value:    dat[:length],
	}, nil
}

func (p rawProperty) parse(nodeName string) any {
	if p.template {
		return parseTemplate(p.value)
	}
	return parseProperty(p.key, nodeName, p.value)
}

// getProperties reads every property before decoding, because decoders can depend on the
// node name and "name" is not necessarily the first property.
func getProperties(buffer io.Reader, node Node) (string, DeviceTree, error) {
	var nodeName string
	var raw []rawProperty
	for range int(node.NumProperties) {
		prop, err := readNodeProperty(buffer)
		if err != nil {
			return "", DeviceTree{}, err
		}
		if strings.EqualFold("name", prop.key) {
			name := bytes.TrimRight(prop.value, "\x00")
			if len(name) == 0 || !isPrintable(name) {
				return "", DeviceTree{}, fmt.Errorf("invalid node name: expected non-empty printable text")
			}
			nodeName = string(name)
			continue
		}
		raw = append(raw, prop)
	}
	props := Properties{}
	for _, prop := range raw {
		props[prop.key] = prop.parse(nodeName)
	}
	return nodeName, DeviceTree{nodeName: props}, nil
}

func parseProperties(r io.Reader, node Node, parent DeviceTree) (DeviceTree, error) {

	name, parent, err := getProperties(r, node)
	if err != nil {
		return DeviceTree{}, err
	}

	children := []DeviceTree{}
	for range int(node.NumChildren) {
		cNode, err := parseNode(r)
		if err != nil {
			return DeviceTree{}, err
		}

		cProps, err := parseProperties(r, cNode, DeviceTree{})
		if err != nil {
			return DeviceTree{}, err
		}
		children = append(children, cProps)
	}
	parent[name]["children"] = children

	return parent, nil
}

func parseDeviceTree(r io.Reader) (*DeviceTree, error) {

	// Read a Node from the buffer
	node, err := parseNode(r)
	if err != nil {
		return nil, err
	}

	dtree, err := parseProperties(r, node, DeviceTree{})
	if err != nil {
		return nil, err
	}

	return &dtree, nil
}

func ParseData(r io.Reader) (*DeviceTree, error) {
	return parseDeviceTree(r)
}

func DecryptIm4pData(data, iv, key []byte) ([]byte, error) {
	i, err := img4.ParsePayload(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IM4P: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	if len(i.Data) < aes.BlockSize {
		return nil, fmt.Errorf("im4p data too short")
	}

	// CBC mode always works in whole blocks.
	if (len(i.Data) % aes.BlockSize) != 0 {
		return nil, fmt.Errorf("im4p data is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(i.Data, i.Data)

	if bytes.Contains(i.Data[:4], []byte("bvx2")) {
		utils.Indent(log.Debug, 2)("Detected LZFSE compression")
		dat, err := lzfse.NewDecoder(i.Data).DecodeBuffer()
		if err != nil {
			return nil, fmt.Errorf("failed to lzfse decompress: %v", err)
		}
		return dat, nil
	}

	return i.Data, nil
}

// Parse parses plist files in a local ipsw file
func Parse(ipswPath string, keys ...string) (map[string]*DeviceTree, error) {
	dt := make(map[string]*DeviceTree)

	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %s", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if regexp.MustCompile(`.*DeviceTree.*im4p$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open %s: %v", f.Name, err)
			}
			_, err = io.ReadFull(rc, dtData)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read %s: %v", f.Name, err)
			}
			if len(keys) > 0 {
				ivkey, err := hex.DecodeString(keys[0])
				if err != nil {
					return nil, fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				data, err := DecryptIm4pData(dtData, ivkey[:aes.BlockSize], ivkey[aes.BlockSize:])
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt Img4 DeviceTree: %w", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 device tree data: %w", err)
				}
			} else {
				dt[filepath.Base(f.Name)], err = ParseImg4Data(dtData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %w", err)
				}
			}
		} else if regexp.MustCompile(`.*DeviceTree.*img3$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()
			if len(keys) > 0 {
				ivkey, err := hex.DecodeString(keys[0])
				if err != nil {
					return nil, fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				data, err := img3.Decrypt(dtData, ivkey[:aes.BlockSize], ivkey[aes.BlockSize:])
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt Img3 DeviceTree: %w", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img3 device tree data: %w", err)
				}
			} else {
				dt[filepath.Base(f.Name)], err = ParseImg3Data(dtData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img3 DeviceTree: %w", err)
				}
			}
		}
	}

	return dt, nil
}

// ParseZipFiles parses DeviceTree in remote ipsw zip
func ParseZipFiles(files []*zip.File, keys ...string) (dt map[string]*DeviceTree, err error) {

	dt = make(map[string]*DeviceTree)

	for _, f := range files {
		if regexp.MustCompile(`.*DeviceTree.*im4p$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open %s: %v", f.Name, err)
			}
			_, err = io.ReadFull(rc, dtData)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read %s: %v", f.Name, err)
			}
			if len(keys) > 0 {
				ivkey, err := hex.DecodeString(keys[0])
				if err != nil {
					return nil, fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				data, err := DecryptIm4pData(dtData, ivkey[:aes.BlockSize], ivkey[aes.BlockSize:])
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt Img4 DeviceTree: %w", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 device tree data: %w", err)
				}
			} else {
				dt[filepath.Base(f.Name)], err = ParseImg4Data(dtData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %w", err)
				}
			}
		} else if regexp.MustCompile(`.*DeviceTree.*img3$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()
			if len(keys) > 0 {
				ivkey, err := hex.DecodeString(keys[0])
				if err != nil {
					return nil, fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				data, err := img3.Decrypt(dtData, ivkey[:aes.BlockSize], ivkey[aes.BlockSize:])
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt Img3 DeviceTree: %w", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img3 device tree data: %w", err)
				}
			} else {
				dt[filepath.Base(f.Name)], err = ParseImg3Data(dtData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img3 DeviceTree: %w", err)
				}
			}
		}
	}

	return dt, nil
}

// Extract extracts DeviceTree(s) from ipsw
func Extract(ipsw, destPath string) error {
	_, err := utils.Unzip(ipsw, destPath, func(f *zip.File) bool {
		if regexp.MustCompile(`.*DeviceTree.*im4p$`).MatchString(f.Name) {
			return true
		}
		return regexp.MustCompile(`.*DeviceTree.*img3$`).MatchString(f.Name)
	})

	if err != nil {
		return fmt.Errorf("failed to extract DeviceTree: %w", err)
	}

	return nil
}
