package fw

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/blacktop/ipsw/pkg/bundle"
)

func TestExtractExclaveCoresUnsupportedBundleType(t *testing.T) {
	var data bytes.Buffer
	header := bundle.Header{
		Unknown1: 0x200,
		Unknown2: 0x1400,
		Magic:    [4]byte{'D', 'N', 'U', 'B'},
		Type:     4,
	}
	if err := binary.Write(&data, binary.LittleEndian, header); err != nil {
		t.Fatalf("failed to write test bundle header: %v", err)
	}
	if err := binary.Write(&data, binary.LittleEndian, bundle.Type4{}); err != nil {
		t.Fatalf("failed to write test bundle type 4 header: %v", err)
	}

	_, err := ExtractExclaveCores(data.Bytes(), t.TempDir())
	if !errors.Is(err, ErrUnsupportedExclaveAppBundleType) {
		t.Fatalf("expected unsupported bundle type error, got %v", err)
	}
}
