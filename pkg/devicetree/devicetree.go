package devicetree

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"

	"fmt"
	"io"
	"math"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

// Img4 DeviceTree object
type Img4 struct {
	IM4P    string
	Name    string
	Version string
	Data    []byte
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
type Properties map[string]interface{}

// DeviceTree object
type DeviceTree map[string]Properties

// Summary object
type Summary struct {
	ProductName string
	BoardConfig string
	Model       string
}

// Summary prints out a summary of the DeviceTree
func (dtree *DeviceTree) Summary() (*Summary, error) {
	summary := &Summary{}

	children := (*dtree)["device-tree"]["children"]

	switch reflect.TypeOf(children).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(children)
		for i := 0; i < s.Len(); i++ {
			child := s.Index(i)
			c := child.Interface().(DeviceTree)
			if product, ok := (c)["product"]["product-name"].(string); ok {
				summary.ProductName = product
			}
		}
	}

	if model, ok := (*dtree)["device-tree"]["model"].(string); ok {
		summary.Model = model
		compatible := (*dtree)["device-tree"]["compatible"]
		switch reflect.TypeOf(compatible).Kind() {
		case reflect.Slice:
			s := reflect.ValueOf(compatible)
			for i := 0; i < s.Len(); i++ {
				elem := s.Index(i).String()
				if !strings.Contains(elem, "Apple") && !strings.Contains(elem, model) {
					summary.BoardConfig = elem
				}
			}
		}
	} else {
		return nil, fmt.Errorf("devicetree model is not a string")
	}

	return summary, nil
}

// GetProductName returns the device-trees product names
func (dtree *DeviceTree) GetProductName() (string, error) {
	children := (*dtree)["device-tree"]["children"]

	switch reflect.TypeOf(children).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(children)
		for i := 0; i < s.Len(); i++ {
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
			for i := 0; i < s.Len(); i++ {
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

func isASCIIPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func findDeviceTreesInList(list []string) []string {
	var validDT = regexp.MustCompile(`.*DeviceTree.*im4p$`)
	dTrees := []string{}
	for _, v := range list {
		if validDT.MatchString(v) {
			dTrees = append(dTrees, v)
		}
	}
	return dTrees
}

func parseValue(value []byte) interface{} {
	// remove trailing NULLs
	value = bytes.TrimRight(value[:], "\x00")
	// value is a string
	if isASCIIPrintable(string(value)) {
		return string(value)
	}
	parts := bytes.Split(value, []byte("\x00"))
	// value is a string array
	if len(parts) > 1 {
		var values []string
		for _, part := range parts {
			if len(string(part)) > 0 {
				if isASCIIPrintable(string(part)) {
					values = append(values, string(part))
				} // else {
				// 	values = append(values, base64.StdEncoding.EncodeToString(value))
				// }
			}
		}
		return values
	}
	if len(value) < 3 {
		i, _ := binary.Uvarint(value)
		return i
	}
	// value is data
	return base64.StdEncoding.EncodeToString(value)
}

func parseNode(buffer io.Reader) (Node, error) {
	var node Node
	// Read a Node from the buffer
	if err := binary.Read(buffer, binary.LittleEndian, &node); err != nil {
		return Node{}, err
	}
	return node, nil
}

func parseNodeProperty(buffer io.Reader) (string, interface{}, error) {
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
	value := parseValue(dat)

	return key, value, nil
}

func getProperties(buffer io.Reader, node Node) (string, DeviceTree, error) {

	var nodeName string
	props := Properties{}

	for index := 0; index < int(node.NumProperties); index++ {
		key, value, err := parseNodeProperty(buffer)
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
	for index := 0; index < int(node.NumChildren); index++ {
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

// Parse parses plist files in a local ipsw file
func Parse(ipswPath string) (map[string]*DeviceTree, error) {
	dt := make(map[string]*DeviceTree)

	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open ipsw as zip")
	}
	defer zr.Close()

	for _, f := range zr.File {
		if regexp.MustCompile(`.*DeviceTree.*im4p$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()

			dt[filepath.Base(f.Name)], err = ParseImg4Data(dtData)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse DeviceTree")
			}
		} else if regexp.MustCompile(`.*DeviceTree.*img3$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()

			dt[filepath.Base(f.Name)], err = ParseImg3Data(dtData)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse DeviceTree")
			}
		}
	}

	return dt, nil
}

// ParseZipFiles parses DeviceTree in remote ipsw zip
func ParseZipFiles(files []*zip.File) (map[string]*DeviceTree, error) {

	var err error

	dt := make(map[string]*DeviceTree)

	for _, f := range files {
		if regexp.MustCompile(`.*DeviceTree.*im4p$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()

			dt[filepath.Base(f.Name)], err = ParseImg4Data(dtData)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse DeviceTree")
			}
		} else if regexp.MustCompile(`.*DeviceTree.*img3$`).MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()

			dt[filepath.Base(f.Name)], err = ParseImg3Data(dtData)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse DeviceTree")
			}
		}
	}

	return dt, nil
}

// Extract extracts DeviceTree(s) from ipsw
func Extract(ipsw, destPath string) error {
	_, err := utils.Unzip(ipsw, destPath, func(f *zip.File) bool {
		var validDT = regexp.MustCompile(`.*DeviceTree.*im4p$`)
		if validDT.MatchString(f.Name) {
			return true
		}
		validDT = regexp.MustCompile(`.*DeviceTree.*img3$`)
		if validDT.MatchString(f.Name) {
			return true
		}
		return false
	})

	if err != nil {
		return errors.Wrap(err, "failed to extract DeviceTree from ipsw")
	}

	return nil
}
