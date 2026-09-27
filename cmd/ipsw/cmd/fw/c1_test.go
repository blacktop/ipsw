package fw

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/blacktop/ipsw/pkg/ftab"
)

func TestC1InfoLeavesNoExtractedFiles(t *testing.T) {
	var data bytes.Buffer
	if err := binary.Write(&data, binary.LittleEndian, ftab.Header{Magic: ftab.FtabMagic}); err != nil {
		t.Fatal(err)
	}
	testFirmwareInfoFiles(t, c1Cmd, "fw.c1", "Firmware/c4000/Release/ftab.bin", data.Bytes())
}
