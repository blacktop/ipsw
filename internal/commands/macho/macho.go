package macho

import (
	"fmt"

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

	engine := disass.NewMachoDisass(m, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
		Middle:       text.Addr + text.Size,
	})

	return engine.FindSwiftStrings()
}
