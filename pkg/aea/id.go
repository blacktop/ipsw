package aea

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
)

func ID(in string) ([32]byte, error) {
	f, err := os.Open(in)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()

	var header Header
	if err := binary.Read(f, binary.LittleEndian, &header); err != nil {
		return [32]byte{}, err
	}

	f.Seek(0, io.SeekStart) // rewind

	data := make([]byte,
		binary.Size(header)+
			int(header.AuthDataLength)+
			int(32)+ // main salt
			binary.Size(encRootHeader{}),
	)
	if _, err := f.Read(data); err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(data), nil
}
