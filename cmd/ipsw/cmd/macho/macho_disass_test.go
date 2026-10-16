package macho

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"

	"github.com/blacktop/go-macho/types"
)

func TestMachoDisassIPAEntry(t *testing.T) {
	const base = uint64(0x100000000)
	const entryOffset = 0x200
	data := make([]byte, entryOffset+8)
	segment := types.Segment64{LoadCmd: types.LC_SEGMENT_64, Len: 72,
		Addr: base, Memsz: 0x1000, Filesz: uint64(len(data))}
	copy(segment.Name[:], "__TEXT")
	var header bytes.Buffer
	for _, value := range []any{
		types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64,
			Type: types.MH_EXECUTE, NCommands: 2, SizeCommands: 96},
		segment,
		types.EntryPointCmd{LoadCmd: types.LC_MAIN, Len: 24, EntryOffset: entryOffset},
	} {
		if err := binary.Write(&header, binary.LittleEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	copy(data, header.Bytes())
	binary.LittleEndian.PutUint32(data[entryOffset:], 0xd2800540)   // mov x0, #42
	binary.LittleEndian.PutUint32(data[entryOffset+4:], 0xd65f03c0) // ret
	name := writeMachoTestIPA(t, data)

	flags := machoDisassCmd.Flags()
	for name, value := range map[string]string{"entry": "true", "count": "2", "quiet": "true"} {
		flag := flags.Lookup(name)
		old, changed := flag.Value.String(), flag.Changed
		t.Cleanup(func() {
			if err := flags.Set(name, old); err != nil {
				t.Error(err)
			}
			flag.Changed = changed
		})
		if err := flags.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	output, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdout := os.Stdout
	os.Stdout = output
	defer func() { os.Stdout = stdout }()
	if err := machoDisassCmd.RunE(machoDisassCmd, []string{name}); err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result), "0x100000200") || !strings.Contains(string(result), "ret") {
		t.Fatalf("missing entry-point instructions: %q", result)
	}
}
