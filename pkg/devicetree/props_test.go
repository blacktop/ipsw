package devicetree

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func encodeProperty(t *testing.T, name string, value []byte, template bool, padByte byte) []byte {
	t.Helper()
	var prop NodeProperty
	copy(prop.Name[:], name)
	prop.Length = uint32(len(value))
	if template {
		prop.Length |= 0x80000000
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, prop); err != nil {
		t.Fatalf("encode %s header: %v", name, err)
	}
	buf.Write(value)
	for buf.Len()%4 != 0 {
		buf.WriteByte(padByte)
	}
	return buf.Bytes()
}

func le32s(vals ...uint32) []byte {
	out := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}

func f32s(vals ...float32) []byte {
	out := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(out[i*4:], math.Float32bits(v))
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func cat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

type propCase struct {
	name  string
	key   string
	value []byte
	want  any
}

func runNodePropertyCases(t *testing.T, tests []propCase, template bool) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := encodeProperty(t, tt.key, tt.value, template, 0)
			prop, err := readNodeProperty(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("readNodeProperty: %v", err)
			}
			if prop.key != tt.key {
				t.Fatalf("key = %q, want %q", prop.key, tt.key)
			}
			if got := prop.parse("node"); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("value = %#v (%T), want %#v (%T)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestParseNodePropertyStrings(t *testing.T) {
	runNodePropertyCases(t, []propCase{
		{"empty", "interrupt-controller", nil, nil},
		{"string", "device_type", []byte("cpu\x00"), "cpu"},
		{"one char string", "cluster-type", []byte("E\x00"), "E"},
		{"unterminated FourCC", "role", []byte(" OIS"), " OIS"},
		{"unterminated FourCC array", "input-data-selectors", []byte("1imi2imi"), "1imi2imi"},
		{"padded cluster-type", "cluster-type", []byte("P\x00\x00\x00"), "P"},
		{"padded soc-generation", "soc-generation", []byte("H9\x00\x00"), "H9"},
		{"8 byte padded string", "AAPL,slot-name", []byte("Slot-0\x00\x00"), "Slot-0"},
		{"8 byte padded 4 chars", "x", []byte("ABCD\x00\x00\x00\x00"), "ABCD"},
		{"fixed width buffer", "boot-type", []byte("diag\x00\x00\x00\x00\x00\x00\x00\x00"), "diag"},
		{"short padded buffer", "x", []byte("abcd\x00\x00"), "abcd"},
		{"string list", "clock-names", []byte("apple,everest\x00ARM,v8\x00"), []string{"apple,everest", "ARM,v8"}},
		{"string list with padding", "x", []byte("ab\x00cd\x00\x00\x00"), []string{"ab", "cd"}},
		{"size prefix is not a string", "hid-merge-personality", cat(le32s(6), []byte("abcdef\x00\x00")), Data(cat(le32s(6), []byte("abcdef\x00\x00")))},
	}, false)
}

func TestParseCStringProperties(t *testing.T) {
	for _, key := range []string{"model", "cluster-type", "soc-generation", "platform-name"} {
		for _, tt := range []struct {
			name         string
			value        []byte
			want         any
			wantPlatform any
		}{
			{"empty", nil, nil, ""},
			{"NUL only", []byte{0}, Data{0}, ""},
			{"all NUL", []byte{0, 0, 0, 0}, Data{0, 0, 0, 0}, ""},
			{"control byte", []byte{'H', '\n', 0}, Data{'H', '\n', 0}, Data{'H', '\n', 0}},
			{"embedded NUL", []byte{'H', 0, '9', 0}, Data{'H', 0, '9', 0}, Data{'H', 0, '9', 0}},
			{"invalid UTF-8", []byte{0xff, 0xfe, 0}, Data{0xff, 0xfe, 0}, Data{0xff, 0xfe, 0}},
			{"unterminated", []byte("H9"), "H9", "H9"},
			{"terminated", []byte("H9\x00"), "H9", "H9"},
			{"padded", []byte("H9\x00\x00"), "H9", "H9"},
		} {
			t.Run(key+"/"+tt.name, func(t *testing.T) {
				want := tt.want
				if key == "platform-name" {
					want = tt.wantPlatform
				}
				prop, err := readNodeProperty(bytes.NewReader(encodeProperty(t, key, tt.value, false, 0xff)))
				if err != nil {
					t.Fatal(err)
				}
				got := prop.parse("device-tree")
				if !reflect.DeepEqual(got, want) {
					t.Errorf("value = %#v (%T), want %#v (%T)", got, got, want, want)
				}
				if _, malformed := want.(Data); malformed {
					encoded, err := json.Marshal(got)
					if err != nil {
						t.Fatal(err)
					}
					var decoded []byte
					if err := json.Unmarshal(encoded, &decoded); err != nil || !bytes.Equal(decoded, tt.value) {
						t.Errorf("JSON %s did not preserve original bytes: %v", encoded, err)
					}
				}
				if key == "model" {
					dt := DeviceTree{"device-tree": Properties{"model": got, "children": []DeviceTree{}}}
					summary, err := dt.Summary()
					if model, valid := want.(string); valid {
						if err != nil || summary.ProductType != model {
							t.Fatalf("Summary = %#v, %v; want model %q", summary, err, model)
						}
					} else if err == nil {
						t.Fatalf("Summary accepted an invalid model: %#v", summary)
					}
				}
			})
		}
	}
}

func TestEmptyPlatformNameOutput(t *testing.T) {
	for _, size := range []int{0, 1, 4, 32} {
		prop, err := readNodeProperty(bytes.NewReader(encodeProperty(t, "platform-name", make([]byte, size), false, 0xff)))
		if err != nil {
			t.Fatal(err)
		}
		props := Properties{prop.key: prop.parse("device-tree")}
		encoded, err := json.Marshal(props)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != `{"platform-name":""}` {
			t.Errorf("%d-byte platform-name: JSON = %s", size, encoded)
		}
		var out strings.Builder
		printNode(&out, props, 2)
		if out.String() != "  platform-name: \"\"\n" {
			t.Errorf("%d-byte platform-name: text = %q", size, out.String())
		}
	}
}

func TestParseNodePropertyNumbers(t *testing.T) {
	runNodePropertyCases(t, []propCase{
		{"u8", "x", []byte{1}, uint8(1)},
		{"u16", "x", []byte{1, 2}, uint16(0x0201)},
		{"i16", "x", []byte{0, 0xff}, int16(-256)},
		{"u16 control char", "x", []byte{0x0a, 0}, uint16(10)},
		{"printable 4 byte int", "sid-mask", le32s(0x3f), uint32(0x3f)},
		{"control char int", "msgbox-mailbox-num", le32s(9), uint32(9)},
		{"whitespace is not text", "cpu-avg-limiter-kp", unhex(t, "703d0a00"), uint32(0x000a3d70)},
		{"whitespace only", "x", le32s(0x0a0d0a0d), uint32(0x0a0d0a0d)},
		{"tab inside short value", "x", []byte("a\tb\x00"), uint32(0x00620961)},
		{"DEL is not printable", "x", []byte{0x7f, 'a', 'b', 'c'}, uint32(0x6362617f)},
		{"unterminated binary int", "pci-max-latency", le32s(0x10080808), uint32(0x10080808)},
		{"i32", "cpu-power-zone-target-0", unhex(t, "0000ffff"), int32(-65536)},
		{"inner NUL list rejected", "tlimit", unhex(t, "3f3f003f"), uint32(0x3f003f3f)},
		{"8 byte small int", "sensor-offset-readSum", unhex(t, "5440000000000000"), uint64(0x4054)},
		{"8 byte short text is int", "x", []byte("abc\x00\x00\x00\x00\x00"), uint64(0x636261)},
		{"non-text part is int", "pci-l1pm-control", unhex(t, "0f00554000000000"), uint64(0x4055000f)},
		{"i64", "mic-config", unhex(t, "0100ffffffffffff"), int64(-65535)},
		{"size prefix 8 bytes", "x", cat(le32s(4), []byte("abcd")), uint64(0x6463626100000004)},
		{"AAPL,phandle", "AAPL,phandle", le32s(0x00434241), uint32(0x00434241)},
	}, false)
}

func TestParseNodePropertyData(t *testing.T) {
	short := []byte("abc\x00\x00\x00")
	sizePrefixed := cat(le32s(3), []byte("abcX"), make([]byte, 4))
	runNodePropertyCases(t, []propCase{
		{"non-ASCII u32s are not dropped", "dma-channels", le32s(197, 157, 117), Data(le32s(197, 157, 117))},
		{"records with empty parts", "instance", []byte("TRAD\x00\x00\x00\x00DART\x00\x00\x00\x00"), Data("TRAD\x00\x00\x00\x00DART\x00\x00\x00\x00")},
		{"short padded text", "x", short, Data(short)},
		{"size prefixed table", "ap-wake-sources", sizePrefixed, Data(sizePrefixed)},
		{"all zero", "zeros", make([]byte, 16), 0},
		{"odd length", "blob", []byte{1, 2, 3, 4, 5}, Data{1, 2, 3, 4, 5}},
	}, false)
}

func TestParseNodePropertyTemplate(t *testing.T) {
	runNodePropertyCases(t, []propCase{
		{"syscfg placeholder", "backing-color", []byte("syscfg/CLBG\x00"), "syscfg/CLBG"},
		{"typed key stays a string", "interrupts", []byte("syscfg/ABCD\x00"), "syscfg/ABCD"},
		{"padded", "x", []byte("ab\x00\x00"), "ab"},
		{"binary is lossless", "backing-color", []byte{0x80, 0xff, 0x01, 's', 0}, Data{0x80, 0xff, 0x01, 's', 0}},
		{"all zero", "x", make([]byte, 4), 0},
	}, true)
}

func TestParseNodePropertyIgnoresPadding(t *testing.T) {
	raw := cat(
		encodeProperty(t, "role", []byte("ab\x00"), false, 0xff),
		encodeProperty(t, "blob", []byte{1, 2, 3, 4, 5}, false, 0xee),
	)
	r := bytes.NewReader(raw)
	for _, want := range []any{"ab", Data{1, 2, 3, 4, 5}} {
		prop, err := readNodeProperty(r)
		if err != nil {
			t.Fatalf("readNodeProperty: %v", err)
		}
		if got := prop.parse("node"); !reflect.DeepEqual(got, want) {
			t.Fatalf("value = %#v, want %#v", got, want)
		}
	}
	if r.Len() != 0 {
		t.Fatalf("reader has %d unread bytes; padding was not consumed", r.Len())
	}
}

func TestParseNodePropertyTruncated(t *testing.T) {
	raw := encodeProperty(t, "blob", []byte{1, 2, 3, 4, 5, 6, 7, 8}, false, 0)
	if _, err := readNodeProperty(bytes.NewReader(raw[:len(raw)-2])); err == nil {
		t.Fatal("expected an error for a truncated property value")
	}
	if _, err := readNodeProperty(bytes.NewReader(raw[:10])); err == nil {
		t.Fatal("expected an error for a truncated property header")
	}
}

func TestGetProperties(t *testing.T) {
	tests := []struct {
		name     string
		props    [][]byte
		wantNode string
		wantKey  string
		want     any
	}{
		{
			name:     "padded 4 byte name",
			props:    [][]byte{encodeProperty(t, "name", []byte("ab\x00\x00"), false, 0), encodeProperty(t, "model", []byte("x\x00"), false, 0)},
			wantNode: "ab", wantKey: "model", want: "x",
		},
		{
			name:     "padded 8 byte name",
			props:    [][]byte{encodeProperty(t, "name", []byte("abc\x00\x00\x00\x00\x00"), false, 0), encodeProperty(t, "foo", []byte("bar\x00"), false, 0)},
			wantNode: "abc", wantKey: "foo", want: "bar",
		},
		{
			name:     "name after node-scoped property",
			props:    [][]byte{encodeProperty(t, "clocks", pmgrClockRecord(0x1a, 0, 1, 1, "LPPLL_FAST"), false, 0), encodeProperty(t, "name", []byte("pmgr\x00"), false, 0)},
			wantNode: "pmgr", wantKey: "clocks", want: []pmgr_clock{{PerfIdx: 0x1a, Unk: 1, ID: 1, Name: "LPPLL_FAST"}},
		},
		{
			name:     "__MACHO value after name-dependent lookup",
			props:    [][]byte{encodeProperty(t, "value", cat(le32s(1), le32s(0x4000, 0)), false, 0), encodeProperty(t, "name", []byte("__MACHO__TEXT\x00"), false, 0)},
			wantNode: "__MACHO__TEXT", wantKey: "value", want: uint64(0x4000),
		},
		{
			name:     "__MACHO value uses offset/size layout",
			props:    [][]byte{encodeProperty(t, "name", []byte("__MACHO__TEXT\x00"), false, 0), encodeProperty(t, "value", cat(le32s(1), le32s(0x4000, 0)), false, 0)},
			wantNode: "__MACHO__TEXT", wantKey: "value", want: uint64(0x4000),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := Node{NumProperties: uint32(len(tt.props))}
			name, dt, err := getProperties(bytes.NewReader(cat(tt.props...)), node)
			if err != nil {
				t.Fatalf("getProperties: %v", err)
			}
			if name != tt.wantNode {
				t.Fatalf("node name = %q, want %q", name, tt.wantNode)
			}
			if got := dt[name][tt.wantKey]; !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("%s = %#v (%T), want %#v (%T)", tt.wantKey, got, got, tt.want, tt.want)
			}
		})
	}
}

func TestParseDataPropertyCountAllocation(t *testing.T) {
	// A moderate count catches metadata-sized preallocation without risking an OOM
	// when this regression test runs against the old parser.
	r := bytes.NewReader(le32s(1<<16, 0))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := ParseData(r)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("ParseData error = %v, want EOF", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("header-only tree allocated %d bytes, want less than 1 MiB", allocated)
	}
}

func TestParseDataInvalidNodeNames(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value []byte
	}{
		{"empty", nil},
		{"NUL", []byte{0}},
		{"all NUL", []byte{0, 0, 0, 0}},
		{"control byte", []byte{'a', '\n', 0}},
		{"embedded NUL", []byte{'a', 0, 'b', 0}},
		{"binary byte", []byte{0xff, 0}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw := cat(le32s(1, 0), encodeProperty(t, "name", tt.value, false, 0xff))
			dt, err := ParseData(bytes.NewReader(raw))
			if err == nil || !strings.Contains(err.Error(), "invalid node name") {
				t.Fatalf("ParseData error = %v, want invalid node name", err)
			}
			if dt != nil {
				t.Fatalf("ParseData returned a tree for an invalid name: %#v", dt)
			}
		})
	}
}

func TestParseDataMaxPropertyCount(t *testing.T) {
	if _, err := ParseData(bytes.NewReader(le32s(math.MaxUint32, 0))); !errors.Is(err, io.EOF) {
		t.Fatalf("ParseData error = %v, want EOF", err)
	}
}

func dapfEntryBytes(start, end uint64, tail byte) []byte {
	out := make([]byte, 16)
	binary.LittleEndian.PutUint64(out, start)
	binary.LittleEndian.PutUint64(out[8:], end)
	return cat(out, le32s(1, 2, 3, 4, 5, 6, 7, 8), []byte{9, 10, 11, tail})
}

func TestParseDAPFVariants(t *testing.T) {
	for _, tt := range []struct {
		name    string
		pad     []byte
		jsonPad string
		textPad string
	}{
		{"B", []byte{0x12, 0x34, 0x56, 0x78}, `,"pad":2018915346`, " pad=0x78563412"},
		{"C", []byte{0x12, 0x34, 0x56}, `,"pad":[18,52,86]`, " pad=[0x12 0x34 0x56]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			first := cat(dapfEntryBytes(0x1000, 0x1003, 12), tt.pad)
			second := cat(dapfEntryBytes(0x2000, 0x2003, 13), tt.pad)
			for _, count := range []int{1, 2} {
				value := first
				want := `[{"start":4096,"end":4099,"r20":1,"unk1":2,"r4":3,"unk2":[4,5,6,7,8],"unk3":9,"r0h":10,"r0l":11,"unk4":12` + tt.jsonPad + `}`
				if count == 2 {
					value = cat(first, second)
					want += `,{"start":8192,"end":8195,"r20":1,"unk1":2,"r4":3,"unk2":[4,5,6,7,8],"unk3":9,"r0h":10,"r0l":11,"unk4":13` + tt.jsonPad + `}`
				}
				want += `]`
				// Nonzero property alignment bytes must not enter the C record's pad.
				prop, err := readNodeProperty(bytes.NewReader(encodeProperty(t, "dapf-instance-2", value, false, 0xff)))
				if err != nil {
					t.Fatal(err)
				}
				got := prop.parse("dart")
				encoded, err := json.Marshal(got)
				if err != nil {
					t.Fatal(err)
				}
				if string(encoded) != want {
					t.Fatalf("%d records: JSON = %s, want %s", count, encoded, want)
				}
				var out strings.Builder
				printNode(&out, Properties{prop.key: got}, 2)
				if strings.Count(out.String(), tt.textPad) != count {
					t.Fatalf("%d records: missing pads in text: %s", count, out.String())
				}
			}
		})
	}
}

func TestParseDAPFSelection(t *testing.T) {
	for _, tt := range []struct {
		name  string
		size  int
		count int
	}{
		{"52 before 56", 728, 14},
		{"52 before 55", 2860, 55},
		{"56 before 55", 3080, 55},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := reflect.ValueOf(parseProperty("dapf-instance-0", "dart", make([]byte, tt.size)))
			if got.Kind() != reflect.Slice {
				t.Fatalf("got %T, want a slice", got.Interface())
			}
			if got.Len() != tt.count {
				t.Fatalf("got %T, length %d; want %d records", got.Interface(), got.Len(), tt.count)
			}
		})
	}
	for _, size := range []int{1, 51, 53, 54, 57, 109, 111} {
		value := make([]byte, size)
		if got := parseProperty("dapf-instance-0", "dart", value); !reflect.DeepEqual(got, Data(value)) {
			t.Errorf("length %d: got %#v, want Data", size, got)
		}
	}
}

func TestParseProperty(t *testing.T) {
	dapf := cat(dapfEntryBytes(0x381618000, 0x381618003, 12), dapfEntryBytes(0x3c5c58000, 0x3c5c58003, 13))
	dapfEntry := func(start, end uint64, tail uint8) DAPFEntry {
		return DAPFEntry{Start: start, End: end, R20: 1, Unk1: 2, R4: 3, Unk2: [5]uint32{4, 5, 6, 7, 8}, Unk3: 9, R0h: 10, R0l: 11, Unk4: tail}
	}
	pmap := cat(le32s(0x1000, 0, 0x4000, 0, 7), []byte("TRAD"))
	uuid := unhex(t, "000102030405060708090a0b0c0d0e0f")
	oipg := cat([]byte("OIPG"), le32s(0x70, 0))
	odd := []byte{1, 2, 3, 4, 5, 6}
	tests := []propCase{
		{"function with args", "function-perst", unhex(t, "0c0100004f4950470400000000000000"), Function{Phandle: 0x10c, Name: "GPIO", Args: []uint32{4, 0}}},
		{"function without args", "function-cpu_idle", cat(le32s(48), []byte("Iupc")), Function{Phandle: 48, Name: "cpuI"}},
		{"function FourCC only", "function-bootstrap_lock", []byte("KCOL"), "LOCK"},
		{"function phandle only", "function-enable_core", le32s(39), Function{Phandle: 39}},
		{"function table is data", "function-perf-boost", cat(le32s(0xafc8, 0), []byte("DCS_PWR_GATE\x00\x00\x00\x00")), Data(cat(le32s(0xafc8, 0), []byte("DCS_PWR_GATE\x00\x00\x00\x00")))},
		{"function FourCC first is data", "function-perst-tupai", oipg, Data(oipg)},
		{"function printable phandle is data", "function-foo", []byte("abcdefgh\x00\x00\x00\x00"), Data("abcdefgh\x00\x00\x00\x00")},
		{"function odd length is data", "function-x", odd, Data(odd)},
		{"function empty", "function-x", nil, nil},
		{"function prefix needs dash", "functionx", cat(le32s(35), []byte("Gklc")), uint64(0x636c6b4700000023)},
		{"interrupts", "interrupts", le32s(197, 157, 117), []uint32{197, 157, 117}},
		{"single gate is a list", "clock-gates", le32s(64), []uint32{64}},
		{"power gates", "power-gates", unhex(t, "90000010"), []uint32{0x10000090}},
		{"service gates", "service-gates", le32s(14), []uint32{14}},
		{"clock ids", "clock-ids", le32s(4), []uint32{4}},
		{"gates odd length", "power-gates", odd, Data(odd)},
		{"phandle is a list", "interrupt-parent", le32s(45), []uint32{45}},
		{"phandle list", "interrupt-parent", unhex(t, "740100000601000074010000"), []uint32{0x174, 0x106, 0x174}},
		{"iommu parent odd length", "iommu-parent", odd, Data(odd)},
		{"iommu parent empty", "iommu-parent", nil, nil},
		{"dapf", "dapf-instance-1", dapf, []DAPFEntry{dapfEntry(0x381618000, 0x381618003, 12), dapfEntry(0x3c5c58000, 0x3c5c58003, 13)}},
		{"dapf bad length", "dapf-instance-0", dapf[:51], Data(dapf[:51])},
		{"special region frame", "special-region-1-frame", f32s(461, 42, 284, 110), []float32{461, 42, 284, 110}},
		{"special region web frame", "special-region-1-web-frame", f32s(608, 42, 27, 110), []float32{608, 42, 27, 110}},
		{"special region NaN", "special-region-1-frame", le32s(0x7fc00000, 0, 0, 0), Data(le32s(0x7fc00000, 0, 0, 0))},
		{"special region Inf", "special-region-1-frame", le32s(0x7f800000, 0, 0, 0), Data(le32s(0x7f800000, 0, 0, 0))},
		{"special region odd length", "special-region-1-frame", odd, Data(odd)},
		{"special region needs frame suffix", "special-region-1-type", []byte("Jindo\x00"), "Jindo"},
		{"sptm allow reg", "sptm-allow-reg", le32s(0x8de00000, 0x2, 0x140000, 0), pmgr_reg{Addr: 0x28de00000, Size: 0x140000}},
		{"sptm allow reg list", "sptm-allow-internal-reg", le32s(0x5d000000, 0, 0x4000, 0, 0x60000000, 0, 0x8000, 0), []pmgr_reg{{Addr: 0x5d000000, Size: 0x4000}, {Addr: 0x60000000, Size: 0x8000}}},
		{"reg", "reg", le32s(0x1000, 0, 0x4000, 0), pmgr_reg{Addr: 0x1000, Size: 0x4000}},
		{"uuid", "uuid", uuid, "00010203-0405-0607-0809-0A0B0C0D0E0F"},
		{"uuid wrong length", "uuid", cat(uuid, []byte{0x10}), Data(cat(uuid, []byte{0x10}))},
		{"pmap io ranges", "pmap-io-ranges", pmap, []PmapIORange{{Start: 0x1000, Size: 0x4000, Flags: 7, Name: [4]byte{'D', 'A', 'R', 'T'}}}},
		{"model", "model", []byte("iPhone19,2\x00"), "iPhone19,2"},
		{"compatible single", "compatible", []byte("gpu,t8160\x00"), "gpu,t8160"},
		{"compatible list", "compatible", []byte("V63AP\x00iPhone19,2\x00AppleARM\x00"), []string{"V63AP", "iPhone19,2", "AppleARM"}},
		{"compatible keeps empty entries", "compatible", []byte("N90AP\x00\x00iPhone1,1\x00AppleARM\x00"), []string{"N90AP", "", "iPhone1,1", "AppleARM"}},
		{"compatible leading NUL", "compatible", []byte("\x00gpio,t8101\x00"), []string{"", "gpio,t8101"}},
		{"compatible binary", "compatible", le32s(197, 157), uint64(0x9d000000c5)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProperty(tt.key, "node", tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseProperty(%q) = %#v (%T), want %#v (%T)", tt.key, got, got, tt.want, tt.want)
			}
		})
	}
}

func pmgrClockRecord(perfIdx, perfBlock, unk, id byte, name string) []byte {
	rec := make([]byte, 24)
	rec[0], rec[1], rec[2], rec[3] = perfIdx, perfBlock, unk, id
	copy(rec[8:], name)
	return rec
}

func TestParsePmgrClocks(t *testing.T) {
	clocks := cat(pmgrClockRecord(0x1a, 0, 1, 1, "LPPLL_FAST"), pmgrClockRecord(0x1b, 0, 1, 2, "AOP_CLK_SEL_0"))
	badConst := bytes.Clone(clocks)
	badConst[4] = 1
	tests := []struct {
		name     string
		nodeName string
		value    []byte
		want     any
	}{
		{"pmgr clocks", "pmgr", clocks, []pmgr_clock{
			{PerfIdx: 0x1a, Unk: 1, ID: 1, Name: "LPPLL_FAST"},
			{PerfIdx: 0x1b, Unk: 1, ID: 2, Name: "AOP_CLK_SEL_0"},
		}},
		{"non-zero constant is data", "pmgr", badConst, Data(badConst)},
		{"bad length is data", "pmgr", clocks[:23], Data(clocks[:23])},
		{"other nodes are generic", "clpc", clocks, Data(clocks)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProperty("clocks", tt.nodeName, tt.value)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("clocks = %#v (%T), want %#v (%T)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestBoardConfig(t *testing.T) {
	dt := DeviceTree{"device-tree": Properties{
		"model":      "iPhone1,1",
		"compatible": []string{"", "iPhone1,1", "N90AP", "AppleARM"},
	}}
	got, err := dt.GetBoardConfig()
	if err != nil {
		t.Fatalf("GetBoardConfig: %v", err)
	}
	if got != "N90AP" {
		t.Fatalf("GetBoardConfig = %q, want %q", got, "N90AP")
	}

	dt["device-tree"]["compatible"] = Data("N90AP\x00AppleARM\x00")
	if got, err := dt.GetBoardConfig(); err == nil {
		t.Fatalf("GetBoardConfig on Data compatible = %q, want error", got)
	}
	delete(dt["device-tree"], "compatible")
	if got, err := dt.GetBoardConfig(); err == nil {
		t.Fatalf("GetBoardConfig without compatible = %q, want error", got)
	}
}

func TestPropertyJSON(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"reg keeps zero address", pmgr_reg{Size: 16384}, `{"addr":0,"size":16384}`},
		{"data is base64", Data{1, 2, 3}, `"AQID"`},
		{"function", Function{Phandle: 35, Name: "clkG", Args: []uint32{1}}, `{"phandle":35,"function":"clkG","args":[1]}`},
		{"empty typed value", parseProperty("clock-gates", "node", nil), `null`},
		{"empty dapf", parseProperty("dapf-instance-0", "node", nil), `null`},
		{"non-finite frame", parseProperty("special-region-1-frame", "product", le32s(0x7fc00000, 0x7f800000, 0, 0)), `"AADAfwAAgH8AAAAAAAAAAA=="`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("json = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestPrintNode(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value any
		want  string
	}{
		{"function", "function-x", Function{Phandle: 7, Name: "clkG", Args: []uint32{1, 0x1234}}, "  function-x: 7:clkG(0x1, 0x1234)\n"},
		{"data", "blob", Data{1, 2, 3, 4, 5}, "  blob: AQIDBAU=\n"},
		{"data with names", "controller", Data("\x01\x00\x00\x00DIE-TEMP\x00\x00DCS-BW\x00\x00"), "  controller: AQAAAERJRS1URU1QAABEQ1MtQlcAAA== [\"DIE-TEMP\" \"DCS-BW\"]\n"},
		{"u32 list", "interrupts", []uint32{1, 2, 3}, "  interrupts: [1 2 3]\n"},
		{"dapf", "dapf-instance-0", []DAPFEntry{{Start: 0x1000, End: 0x1003, R0h: 3}}, "  dapf-instance-0: [start=0x1000 end=0x1003 r20=0x0 unk1=0x0 r4=0x0 unk2=[0x0 0x0 0x0 0x0 0x0] unk3=0x0 r0h=0x3 r0l=0x0 unk4=0x0]\n"},
		{"pmgr clocks", "clocks", []pmgr_clock{{ID: 2, Name: "AOP_CLK_SEL_0", PerfIdx: 0x1b, Unk: 1}}, "  clocks: [id=2 name=\"AOP_CLK_SEL_0\" perf_idx=27 perf_block=0 unk=1]\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			printNode(&out, Properties{tt.key: tt.value}, 2)
			if out.String() != tt.want {
				t.Fatalf("printNode = %q, want %q", out.String(), tt.want)
			}
		})
	}
}
