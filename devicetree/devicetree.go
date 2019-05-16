package devicetree

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/apex/log"
	"github.com/blacktop/partialzip"
	"github.com/pkg/errors"
)

// Asn1 DeviceTree object
type Asn1 struct {
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
// type property map[string]interface{}

// Properties object
type Properties map[string]interface{}

// 	property
// 	Children []DeviceTree `json:"children,omitempty"`
// }

// DeviceTree object
type DeviceTree map[string]Properties

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

// Parse parses a DeviceTree img4 file
func Parse(path string) error {
	log.Info("Parsing DeviceTree")
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return err
	}

	dat := make([]byte, fi.Size())
	_, err = f.Read(dat)
	if err != nil {
		return err
	}

	var a Asn1
	// NOTE: openssl asn1parse -i -inform DER -in DEVICETREE.im4p
	if _, err := asn1.Unmarshal(dat, &a); err != nil {
		return err
	}

	dtree, err := parseDeviceTree(bytes.NewBuffer(a.Data))
	if err != nil {
		return err
	}

	j, err := json.Marshal(dtree)
	if err != nil {
		return err
	}

	fmt.Println(string(j))

	return nil
}

// RemoteParse parses a DeviceTree img4 file in a remote ipsw file
func RemoteParse(url string) error {

	pzip, err := partialzip.New(url)
	if err != nil {
		return errors.Wrap(err, "failed to create partialzip instance")
	}
	dtrees := findDeviceTreesInList(pzip.List())
	if len(dtrees) > 0 {
		for _, dtree := range dtrees {
			_, err = pzip.Download(dtree)
			if err != nil {
				return errors.Wrap(err, "failed to download file")
			}
			err := Parse(filepath.Base(dtree))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
