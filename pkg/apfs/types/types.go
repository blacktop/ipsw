package types

type prange struct {
	PrStartPaddr uint64
	PrBlockCount uint64
}

type magic [4]byte

func (m magic) String() string {
	return string(m[:])
}
