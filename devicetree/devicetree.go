package devicetree

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math"
	"os"

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
	var vlen uint32
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
			vlen = prop.Length & (math.MaxUint32 >> 1)
			if (vlen % 4) != 0 {
				vlen = vlen + (4 - (vlen % 4))
			}
			dat = make([]byte, vlen)
			if err = binary.Read(buffer, binary.LittleEndian, &dat); err != nil {
				return err
			}
			name := string(bytes.TrimRight(prop.Name[:], "\x00"))
			value := string(bytes.TrimRight(dat[:], "\x00"))
			// values := bytes.Split(bytes.TrimSuffix(dat[:], []byte("\x00")), []byte("\x00"))
			// if len(values) > 1 {
			// 	fmt.Printf("%s =>\n", name)
			// 	for _, v := range values {
			// 		fmt.Printf("\t - %s\n", string(v))
			// 	}
			// } else {
			// 	value := string(values[0])
			fmt.Printf("\t\t- %s => %s\n", name, value)
			// }
		}
	}
	return nil
}
