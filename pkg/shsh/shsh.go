package shsh

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
)

// SHSH object
type SHSH struct {
	ApImg4Ticket []byte
	Generator    string `plist:"generator"`
}

// ParseRAW parses a shsh blob out of a raw dump
func ParseRAW(r io.Reader) error {
	utils.Indent(log.Info, 2)("Parsing shsh")

	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	img4, err := img4.Parse(data)
	if err != nil {
		return err
	}

	// Find ECID property
	var ecid any
	for _, prop := range img4.Manifest.Properties {
		if prop.Name == "ECID" {
			ecid = prop.Value
			break
		}
	}
	if ecid == nil {
		ecid = "unknown"
	}

	shsh := &SHSH{
		Generator: fmt.Sprintf("0x%x", binary.LittleEndian.Uint64(img4.RestoreInfo.RestoreProperties.Bytes)),
		// Use the raw manifest data (skip Context Specific header)
		ApImg4Ticket: img4.Manifest.Raw[4:],
	}

	pDatam, err := plist.MarshalIndent(shsh, plist.XMLFormat, "\t")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%v.dumped.shsh", ecid)
	err = os.WriteFile(name, pDatam, 0660)
	if err != nil {
		return err
	}
	utils.Indent(log.Info, 3)(fmt.Sprintf("Dumped SHSH blob to %s", name))

	return nil
}
