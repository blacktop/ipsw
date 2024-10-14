package macho

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/disass"
)

func FindSwiftStrings(m *macho.File) (map[uint64]string, error) {
	text := m.Section("__TEXT", "__text")
	if text == nil {
		return nil, fmt.Errorf("no __TEXT.__text section found")
	}

	data, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to get __TEXT.__text data: %v", err)
	}

	symbolMap := make(map[uint64]string)

	engine := disass.NewMachoDisass(m, &symbolMap, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
		Middle:       text.Addr + text.Size,
	})

	return engine.FindSwiftStrings()
}

// TODO: add option to dump all strings - https://github.com/robpike/strings/blob/master/strings.go
func GetStrings(m *macho.File) (map[uint64]string, error) {
	strs := make(map[uint64]string)

	for _, sec := range m.Sections {
		if sec.Flags.IsCstringLiterals() || sec.Name == "__os_log" || (sec.Seg == "__TEXT" && sec.Name == "__const") {
			off, err := m.GetOffset(sec.Addr)
			if err != nil {
				return nil, fmt.Errorf("failed to get offset for %s.%s: %v", sec.Seg, sec.Name, err)
			}
			dat := make([]byte, sec.Size)
			if _, err = m.ReadAt(dat, int64(off)); err != nil {
				return nil, fmt.Errorf("failed to read cstring data in %s.%s: %v", sec.Seg, sec.Name, err)
			}

			fmt.Printf("\n[%s.%s]\n", sec.Seg, sec.Name)

			csr := bytes.NewBuffer(dat)

			for {
				pos := sec.Addr + uint64(csr.Cap()-csr.Len())

				s, err := csr.ReadString('\x00')
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, fmt.Errorf("failed to read string: %v", err)
				}

				s = strings.Trim(s, "\x00")

				if len(s) > 0 {
					for _, r := range s {
						if r > unicode.MaxASCII || !unicode.IsPrint(r) {
							continue // skip non-ascii strings
						}
					}
					strs[pos] = s
				}
			}
		}
	}

	return strs, nil
}
