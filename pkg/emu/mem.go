//go:build unicorn

package emu

import "fmt"

type Page struct {
	Addr uint64
	Size uint64
}

func (p *Page) Contains(addr uint64) bool {
	return p.Addr <= addr && addr < p.Addr+p.Size
}

func (p *Page) Overlaps(addr, size uint64) bool {
	return p.Addr < addr+size && addr < p.Addr+p.Size
}

type MemMap struct {
	Pages []*Page
}

func NewMemMap() *MemMap {
	return &MemMap{}
}

func (m *MemMap) Contains(addr uint64) bool {
	for _, p := range m.Pages {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (m *MemMap) Overlaps(addr, size uint64) bool {
	for _, p := range m.Pages {
		if p.Overlaps(addr, size) {
			return true
		}
	}
	return false
}

// Add a new valid page to the map.
func (m *MemMap) Add(addr, size uint64) (uint64, uint64, bool) {
	addr, size = Align(addr, size, true)
	if !m.RangeValid(addr, size) {
		return 0, 0, false
	}
	for i, p := range m.Pages {
		if p.Contains(addr) {
			if p.Overlaps(addr, size) {
				return 0, 0, false
			}
			m.Pages[i].Size = addr - m.Pages[i].Addr
			break
		} else if p.Contains(addr + size) {
			m.Pages[i].Size = addr + size - m.Pages[i].Addr
			break
		}
	}
	for i, p := range m.Pages {
		if p.Contains(addr) {
			m.Pages[i].Addr = addr
			m.Pages[i].Size = size
			return addr, size, true
		}
	}
	m.Pages = append(m.Pages, &Page{addr, size})
	return addr, size, true
}

func (m *MemMap) Remove(addr, size uint64) {
	addr, size = Align(addr, size, true)
	for i, p := range m.Pages {
		if p.Contains(addr) {
			if p.Addr == addr && p.Size == size {
				m.Pages = append(m.Pages[:i], m.Pages[i+1:]...)
				return
			}
			if p.Addr == addr {
				p.Size = p.Addr + p.Size - addr - size
				p.Addr = addr + size
			} else if p.Addr+p.Size == addr+size {
				p.Size = addr - p.Addr
			} else {
				m.Pages = append(m.Pages[:i], m.Pages[i+1:]...)
				m.Add(addr, size)
			}
			return
		}
	}
}

func (m *MemMap) RangeValid(addr, size uint64) bool {
	for _, p := range m.Pages {
		if p.Overlaps(addr, size) {
			return false
		}
	}
	return true
}

func (m *MemMap) Map(addr, size uint64) error {
	addr, size = Align(addr, size, true)
	if !m.RangeValid(addr, size) {
		return fmt.Errorf("invalid range %#x-%#x", addr, addr+size)
	}
	m.Add(addr, size)
	return nil
}

func (m *MemMap) String() string {
	var s string
	for _, p := range m.Pages {
		s += fmt.Sprintf("%#x-%#x\n", p.Addr, p.Addr+p.Size)
	}
	return s
}
