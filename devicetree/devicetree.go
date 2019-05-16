package devicetree

import (
	"encoding/asn1"
	"fmt"
	"os"

	"github.com/apex/log"
)

type DeviceTree interface{}

// Parse parses a DeviceTree img4 file
func Parse(path string) (DeviceTree, error) {
	log.Info("Parsing DeviceTree")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	dat := make([]byte, fi.Size())
	_, err = f.Read(dat)
	if err != nil {
		return nil, err
	}

	var n DeviceTree
	_, err = asn1.Unmarshal(dat, &n)
	if err != nil {
		return nil, err
	}

	fmt.Println("DeviceTree: ", n)
	return n, nil
}
