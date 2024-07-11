package kernel

//go:generate pkl-gen-go pkl/Symbolicator.pkl --base-path github.com/blacktop/ipsw --output-path ../../../

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/signature"
)

func ParseSignatures(dir string) (sigs *signature.Symbolicator, err error) {
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			sigs, err = signature.LoadFromPath(context.Background(), path)
			if err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return sigs, nil
}

func Symbolicate(in string, sigs *signature.Symbolicator) error {
	m, err := macho.Open(in)
	if err != nil {
		return err
	}
	defer m.Close()

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		for _, fs := range m.FileSets() {
			entry, err := m.GetFileSetFileByName(fs.EntryID)
			if err != nil {
				return err
			}
			strs, err := entry.GetCStrings()
			if err != nil {
				return err
			}
			for _, sig := range sigs.Signatures {
				for _, s := range strs {
					if strings.Contains(s, sig.Pattern) {
						log.Infof("Found signature: %s", s)
					}
				}
			}
		}
	} else {

	}

	return nil
}
