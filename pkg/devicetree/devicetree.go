package devicetree

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
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
	"github.com/blacktop/go-macho/types"
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
		compatible := (*dtree)["device-tree"]["compatible"]
		switch reflect.TypeOf(compatible).Kind() {
		case reflect.Slice:
			s := reflect.ValueOf(compatible)
			for i := range s.Len() {
				elem := s.Index(i).String()
				if !strings.Contains(elem, "Apple") && !strings.Contains(elem, model) {
					summary.BoardConfig = elem
				}
			}
		}
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
		compatible := (*dtree)["device-tree"]["compatible"]
		switch reflect.TypeOf(compatible).Kind() {
		case reflect.Slice:
			s := reflect.ValueOf(compatible)
			for i := range s.Len() {
				elem := s.Index(i).String()
				if !strings.Contains(elem, "Apple") && !strings.Contains(elem, model) {
					return elem, nil
				}
			}
		}
	}
	return "", fmt.Errorf("failed to get board-config")
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
	if len(value) == 0 {
		return nil
	}
	switch len(value) {
	case binary.Size(uint8(0)):
		return uint8(value[0])
	case binary.Size(uint16(0)):
		if bytes.HasSuffix(value, []byte("\xff")) {
			return int16(binary.LittleEndian.Uint16(value))
		} else {
			return uint16(binary.LittleEndian.Uint16(value))
		}
	case binary.Size(uint32(0)):
		if bytes.HasSuffix(value, []byte("\xff")) {
			return int32(binary.LittleEndian.Uint32(value))
		} else {
			return uint32(binary.LittleEndian.Uint32(value))
		}
	case binary.Size(uint64(0)):
		if bytes.HasSuffix(value, []byte("\xff")) {
			return int64(binary.LittleEndian.Uint64(value))
		} else {
			return uint64(binary.LittleEndian.Uint64(value))
		}
	default:
		return parseValue(value)
	}
}

func parseValue(value []byte) any {
	if len(value) == 0 {
		return nil
	}

	if !bytes.HasPrefix(value, []byte("\x00")) {
		// remove trailing NULLs
		str := bytes.TrimRight(value[:], "\x00")
		// value is a string
		if utils.IsASCII(string(str)) {
			if len(str) == 0 && len(value) <= binary.Size(uint64(0)) { // detect 0 (not empty string)
				if i, err := binary.Uvarint(value); err > 0 {
					return i
				}
			}
			return string(str)
		}
		if len(value) > 4 {
			size := binary.LittleEndian.Uint32(value[:4])
			if size <= uint32(len(value)-4) && !bytes.Contains(value[4:4+size], []byte("\x00")) {
				if utils.IsASCII(string(value[4 : 4+size])) {
					return string(value[4 : 4+size])
				}
			}
		}
		parts := bytes.Split(str, []byte("\x00"))
		if len(parts) > 1 { // value is a string array
			var values []string
			for _, part := range parts {
				if len(string(part)) > 0 {
					if utils.IsASCII(string(part)) {
						values = append(values, string(part))
					} // else {
					// 	values = append(values, base64.StdEncoding.EncodeToString(value))
					// }
				}
			}
			if len(values) > 0 {
				return values
			}
		}
	}

	if isZero(value) {
		return 0
	}

	switch len(value) {
	case binary.Size(uint8(0)):
		return uint8(value[0])
	case binary.Size(uint16(0)):
		if bytes.HasSuffix(value, []byte("\xff")) {
			return int16(binary.LittleEndian.Uint16(value))
		} else {
			return uint16(binary.LittleEndian.Uint16(value))
		}
	case binary.Size(uint32(0)):
		if bytes.HasSuffix(value, []byte("\xff")) {
			return int32(binary.LittleEndian.Uint32(value))
		} else {
			return uint32(binary.LittleEndian.Uint32(value))
		}
	case binary.Size(uint64(0)):
		if bytes.HasSuffix(value, []byte("\xff")) {
			return int64(binary.LittleEndian.Uint64(value))
		} else {
			return uint64(binary.LittleEndian.Uint64(value))
		}
	}
	// value is data
	return base64.StdEncoding.EncodeToString(value)
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

func parseNodeProperty(buffer io.Reader, propName string) (string, any, error) {
	var nProp NodeProperty
	// Read a NodeProperty from the buffer
	if err := binary.Read(buffer, binary.LittleEndian, &nProp); err != nil {
		return "", nil, err
	}
	// 4 byte align the length
	nProp.Length &= math.MaxInt32
	if (nProp.Length % 4) != 0 {
		nProp.Length = nProp.Length + (4 - (nProp.Length % 4))
	}
	// Read property value from the buffer
	dat := make([]byte, nProp.Length)
	if err := binary.Read(buffer, binary.LittleEndian, &dat); err != nil {
		return "", nil, err
	}

	key := string(bytes.TrimRight(nProp.Name[:], "\x00"))
	var value any
	switch key {
	case "AAPL,phandle":
		value = parseInt(dat)
	case "platform-name":
		value = string(bytes.TrimRight(dat[:], "\x00"))
	case "pmap-io-ranges":
		value = parsePmapIORanges(dat)
	case "ps-regs":
		value = parsePmgrMap(dat)
	case "devices":
		value = parsePmgrDevices(dat)
	case "regions":
		value = parseRegions(dat)
	case "reg-private":
		value = parseAddr(dat)
	case "value":
		if strings.HasPrefix(propName, "__MACHO") {
			value = parseOffSz(dat)
		} else {
			value = parseValue(dat)
		}
	case "reg":
		value = parseReg(dat)
	case "uuid":
		if len(dat) == 16 {
			value = types.UUID(dat).String()
		} else {
			value = parseValue(dat)
		}
	default:
		value = parseValue(dat)
	}

	return key, value, nil
}

func getProperties(buffer io.Reader, node Node) (string, DeviceTree, error) {

	var nodeName string
	props := Properties{}

	for range int(node.NumProperties) {
		key, value, err := parseNodeProperty(buffer, nodeName)
		if err != nil {
			return "", DeviceTree{}, err
		}
		// log.WithFields(log.Fields{"key": key, "value": value}).Debug("extracted property")
		if strings.EqualFold("name", key) {
			if str, ok := value.(string); ok {
				nodeName = str
			} else {
				return "", DeviceTree{}, fmt.Errorf("failed to assigned nodeName to: %#v", value)
			}
		} else {
			props[key] = value
		}
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
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()
			if len(keys) > 0 {
				ivkey, err := hex.DecodeString(keys[0])
				if err != nil {
					return nil, fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				data, err := DecryptIm4pData(dtData, ivkey[:aes.BlockSize], ivkey[aes.BlockSize:])
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %v", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 device tree data: %v", err)
				}
			} else {
				dt[filepath.Base(f.Name)], err = ParseImg4Data(dtData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %v", err)
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
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %v", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 device tree data: %v", err)
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
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()
			if len(keys) > 0 {
				ivkey, err := hex.DecodeString(keys[0])
				if err != nil {
					return nil, fmt.Errorf("failed to decode --iv-key: %v", err)
				}
				data, err := DecryptIm4pData(dtData, ivkey[:aes.BlockSize], ivkey[aes.BlockSize:])
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %v", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 device tree data: %v", err)
				}
			} else {
				dt[filepath.Base(f.Name)], err = ParseImg4Data(dtData)
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %v", err)
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
					return nil, fmt.Errorf("failed to parse Img4 DeviceTree: %v", err)
				}
				dt[filepath.Base(f.Name)], err = parseDeviceTree(bytes.NewReader(data))
				if err != nil {
					return nil, fmt.Errorf("failed to parse Img4 device tree data: %v", err)
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
