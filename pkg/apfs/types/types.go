package types

import "encoding/binary"

type prange struct {
	PrStartPaddr uint64
	PrBlockCount uint64
}

type magic [4]byte

func (m magic) String() string {
	return string(m[:])
}

func CreateChecksum(data []byte) uint64 {
	var sum1, sum2 uint64

	modValue := uint64(2<<31 - 1)

	for i := 0; i < len(data)/4; i++ {
		d := binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
		sum1 = (sum1 + uint64(d)) % modValue
		sum2 = (sum2 + sum1) % modValue
	}

	check1 := modValue - ((sum1 + sum2) % modValue)
	check2 := modValue - ((sum1 + check1) % modValue)

	return (check2 << 32) | check1
}

func VerifyChecksum(data []byte) bool {
	var sum1, sum2 uint64

	modValue := uint64(2<<31 - 1)

	for i := 0; i < len(data)/4; i++ {
		d := binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
		sum1 = (sum1 + uint64(d)) % modValue
		sum2 = (sum2 + sum1) % modValue
	}

	return (sum2<<32)|sum1 != 0
}
