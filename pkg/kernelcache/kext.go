// +build linux,cgo darwin,cgo

package kernelcache

import (
	"bytes"
	"fmt"
	"os"

	"github.com/blacktop/go-macho"
	"howett.net/plist"
)

// KextList lists all the kernel extensions in the kernelcache
func KextList(kernel string) error {
	m, err := macho.Open(kernel)
	if err != nil {
		return err
	}
	defer m.Close()

	for _, sec := range m.Sections {
		if sec.Seg == "__PRELINK_INFO" && sec.Name == "__info" {
			f, err := os.Open(kernel)
			if err != nil {
				return err
			}

			data := make([]byte, sec.Size)
			f.Seek(int64(sec.Offset), os.SEEK_SET)
			_, err = f.Read(data)
			if err != nil {
				return err
			}

			var prelink prelinkInfo
			decoder := plist.NewDecoder(bytes.NewReader(bytes.Trim([]byte(data), "\x00")))
			err = decoder.Decode(&prelink)
			if err != nil {
				return err
			}

			fmt.Println("FOUND:", len(prelink.PrelinkInfoDictionary))
			for _, bundle := range prelink.PrelinkInfoDictionary {
				fmt.Printf("%s (%s)\n", bundle.ID, bundle.Version)
			}
			break
		}
	}
	return nil
}
