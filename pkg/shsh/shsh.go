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

	img4, err := img4.Parse(r)
	if err != nil {
		return err
	}

	shsh := &SHSH{
		Generator: fmt.Sprintf("0x%x", binary.LittleEndian.Uint64(img4.RestoreInfo.Generator.Data)),
		// TODO: this is gross (I'm skipping past the Context Specific type to get to the Im4m)
		ApImg4Ticket: img4.Manifest.ApImg4Ticket.FullBytes[4:],
	}

	pDatam, err := plist.MarshalIndent(shsh, plist.XMLFormat, "\t")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%d.dumped.shsh", img4.Manifest.Properties["ECID"])
	err = os.WriteFile(name, pDatam, 0660)
	if err != nil {
		return err
	}
	utils.Indent(log.Info, 3)(fmt.Sprintf("Dumped SHSH blob to %s", name))

	return nil
}
