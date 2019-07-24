package devicetree

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"

	"fmt"
	"io"
	"math"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
	"github.com/pkg/errors"
	"howett.net/ranger"
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

// Summary prints out a summary of the DeviceTree
func (dtree *DeviceTree) Summary() {
	children := (*dtree)["device-tree"]["children"]

	switch reflect.TypeOf(children).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(children)
		for i := 0; i < s.Len(); i++ {
			child := s.Index(i)
			c := child.Interface().(DeviceTree)
			if _, ok := (c)["product"]; ok {
				utils.Indent(log.Info, 2)(fmt.Sprintf("Product Name: %s", (c)["product"]["product-name"]))
			}
		}
	}

	if model, ok := (*dtree)["device-tree"]["model"].(string); ok {
		utils.Indent(log.Info, 2)(fmt.Sprintf("Model: %s", model))
		compatible := (*dtree)["device-tree"]["compatible"]
		switch reflect.TypeOf(compatible).Kind() {
		case reflect.Slice:
			s := reflect.ValueOf(compatible)
			for i := 0; i < s.Len(); i++ {
				elem := s.Index(i).String()
				if !strings.Contains(elem, "Apple") && !strings.Contains(elem, model) {
					utils.Indent(log.Info, 2)(fmt.Sprintf("BoardConfig: %s", s.Index(i)))
				}
			}
		}
	} else {
		log.Fatal("devicetree model is not a string")
	}
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
		log.WithFields(log.Fields{"key": key, "value": value}).Debug("extracted property")
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

func parseProperties(buffer *bytes.Buffer, node Node, parent DeviceTree) (DeviceTree, error) {

	name, parent, err := getProperties(buffer, node)
	if err != nil {
		return DeviceTree{}, err
	}

	children := []DeviceTree{}
	for index := 0; index < int(node.NumChildren); index++ {
		cNode, err := parseNode(buffer)
		if err != nil {
			return DeviceTree{}, err
		}

		cProps, err := parseProperties(buffer, cNode, DeviceTree{})
		if err != nil {
			return DeviceTree{}, err
		}
		children = append(children, cProps)
	}
	parent[name]["children"] = children

	return parent, nil
}

func parseDeviceTree(buffer *bytes.Buffer) (*DeviceTree, error) {

	// Read a Node from the buffer
	node, err := parseNode(buffer)
	if err != nil {
		return nil, err
	}

	dtree, err := parseProperties(buffer, node, DeviceTree{})
	if err != nil {
		return nil, err
	}

	return &dtree, nil
}

// ParseImg4Data parses a img4 data containing a DeviceTree
func ParseImg4Data(data []byte) (*DeviceTree, error) {

	var i Img4
	// NOTE: openssl asn1parse -i -inform DER -in DEVICETREE.im4p
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, err
	}

	dtree, err := parseDeviceTree(bytes.NewBuffer(i.Data))
	if err != nil {
		return nil, err
	}

	return dtree, nil
}

// RemoteParse parses a DeviceTree img4 file in a remote ipsw file
func RemoteParse(u string) (map[string]*DeviceTree, error) {

	dt := make(map[string]*DeviceTree)
	var validDT = regexp.MustCompile(`.*DeviceTree.*im4p$`)

	url, err := url.Parse(u)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse url")
	}
	reader, err := ranger.NewReader(&ranger.HTTPRanger{URL: url})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ranger reader")
	}
	length, err := reader.Length()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get reader length")
	}
	zr, err := zip.NewReader(reader, length)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create zip reader from ranger reader")
	}

	for _, f := range zr.File {
		if validDT.MatchString(f.Name) {
			dtData := make([]byte, f.UncompressedSize64)
			rc, _ := f.Open()
			io.ReadFull(rc, dtData)
			rc.Close()

			dt[filepath.Base(f.Name)], err = ParseImg4Data(dtData)
			if err != nil {
				return nil, errors.Wrap(err, "failed to parse DeviceTree")
			}
		}
	}

	return dt, nil
}

// Extract extracts DeviceTree(s) from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting DeviceTree from IPSW")
	_, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		var validDT = regexp.MustCompile(`.*DeviceTree.*im4p$`)
		if validDT.MatchString(f.Name) {
			return true
		}
		return false
	})

	if err != nil {
		return errors.Wrap(err, "failed to extract DeviceTree from ipsw")
	}

	// for _, dtree := range dtrees {
	// 	d, err := Open(dtree)
	// 	if err != nil {
	// 		return errors.Wrap(err, "failed to open DeviceTree")
	// 	}
	// 	defer os.Remove(dtree)
	// }

	return nil
}
