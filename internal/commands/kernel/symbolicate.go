package kernel

//go:generate pkl-gen-go pkl/Signature.pkl --base-path github.com/blacktop/ipsw --output-path ../../../

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/signature"
)

func ParseSignatures(dir string) ([]*signature.Signature, error) {
	var sigs []*signature.Signature
	if err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			sig, err := signature.LoadFromPath(context.Background(), path)
			if err != nil {
				return err
			}
			sigs = append(sigs, sig)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return sigs, nil
}

func Symbolicate(in string, sigs []*signature.Signature) error {
	m, err := macho.Open(in)
	if err != nil {
		return err
	}
	defer m.Close()

	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		km, err := m.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return err
		}
		var strs []string
		for _, sec := range km.Sections {
			if sec.Flags.IsCstringLiterals() || sec.Seg == "__TEXT" && sec.Name == "__const" {
				off, err := m.GetOffset(sec.Addr)
				if err != nil {
					return fmt.Errorf("failed to get offset for %s.%s: %v", sec.Seg, sec.Name, err)
				}
				dat := make([]byte, sec.Size)
				if _, err = m.ReadAt(dat, int64(off)); err != nil {
					return fmt.Errorf("failed to read cstring data in %s.%s: %v", sec.Seg, sec.Name, err)
				}

				csr := bytes.NewBuffer(dat)

				for {
					// pos := sec.Addr + uint64(csr.Cap()-csr.Len())

					s, err := csr.ReadString('\x00')

					if err == io.EOF {
						break
					}

					if err != nil {
						return fmt.Errorf("failed to read string: %v", err)
					}

					s = strings.Trim(s, "\x00")

					if len(s) > 0 {
						// TODO: does this skip unicode strings?
						if (sec.Seg == "__TEXT" && sec.Name == "__const") && !utils.IsASCII(s) {
							continue // skip non-ascii strings when dumping __TEXT.__const
						}
						strs = append(strs, s)
						// fmt.Printf("%s: %s\n", symAddrColor("%#09x", pos), symNameColor(fmt.Sprintf("%#v", s)))
					}
				}
			}
		}

		for _, sig := range sigs {
			for _, s := range strs {
				if strings.Contains(s, sig.Pattern) {
					log.Infof("Found signature: %s", s)
				}
			}
		}
	} else {

	}

	return nil
}
