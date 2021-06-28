package dmg

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/blacktop/go-plist"
)

type Block struct {
	Attributes string
	Data       []byte
	ID         string
	Name       string
}

type Plist struct {
	ResourceFork map[string][]Block `plist:"resource-fork,omitempty"`
}

func Read(file string) error {

	dat, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	pl := plist.NewDecoder(bytes.NewReader(dat))

	var dplist Plist
	err = pl.Decode(&dplist)
	if err != nil {
		return fmt.Errorf("failed to parse DMG plist data: %v", err)
	}

	// for _, block := range dplist.ResourceFork["blkx"] {
	// 	ioutil.WriteFile(block.Name, block.Data, 0755)
	// }

	return nil
}
