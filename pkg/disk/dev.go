package disk

import (
	"io"
)

// Device is a disk device object
type Device interface {
	io.ReaderAt
	io.Closer
	GetSize() uint64
}

// // NewDevice creates a new Device to be used as the data store from an APFS instance
// func NewDevice(name string) (Device, error) {
// 	if filepath.Ext(name) == ".dmg" {
// 		return dmg.Open(name)
// 	}

// 	if filepath.Ext(name) == ".sparseimage" {
// 		panic("not implimented yet") // TODO: finish this
// 	}

// 	return nil, fmt.Errorf("")
// }
