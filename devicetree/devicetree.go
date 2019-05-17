package devicetree

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"unicode"

	"github.com/apex/log"
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

func isASCIIPrintable(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
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

	buffer := bytes.NewBuffer(a.Data)

	var node Node
	var prop NodeProperty

	fmt.Println("# DeviceTree")

	for buffer.Len() > 0 {
		if err = binary.Read(buffer, binary.LittleEndian, &node); err != nil {
			return err
		}
		fmt.Printf("\n\tNode: (Properties=%d, Children=%d) \n", node.NumProperties, node.NumChildren)
		for index := 0; index < int(node.NumProperties); index++ {
			if err = binary.Read(buffer, binary.LittleEndian, &prop); err != nil {
				return err
			}
			prop.Length &= math.MaxInt32
			if (prop.Length % 4) != 0 {
				prop.Length = prop.Length + (4 - (prop.Length % 4))
			}
			dat = make([]byte, prop.Length)
			if err = binary.Read(buffer, binary.LittleEndian, &dat); err != nil {
				return err
			}

			name := string(bytes.TrimRight(prop.Name[:], "\x00"))
			value := parseValue(dat)

			fmt.Printf("\t\t- %s => %v\n", name, value)
		}
	}
	return nil
}
