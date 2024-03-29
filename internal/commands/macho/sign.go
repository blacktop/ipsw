package macho

import (
	"errors"
	"fmt"
	"os"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/pkg/codesign"
	cstypes "github.com/blacktop/go-macho/pkg/codesign/types"
)

type SignConfig struct {
	Input  string
	Output string

	Adhoc bool

	Codesign *codesign.Config
}

func AdhocSign(in, out string) error {
	return Sign(&SignConfig{
		Input:  in,
		Adhoc:  true,
		Output: out,
		Codesign: &codesign.Config{
			Flags: cstypes.ADHOC,
		},
	})
}

func Sign(conf *SignConfig) error {
	if fat, err := macho.OpenFat(conf.Input); err == nil { // UNIVERSAL MACHO
		defer fat.Close()
		var slices []string
		for _, arch := range fat.Arches {
			if err := arch.File.CodeSign(conf.Codesign); err != nil {
				return fmt.Errorf("failed to codesign MachO file: %v", err)
			}
			tmp, err := os.CreateTemp("", "macho_"+arch.File.CPU.String())
			if err != nil {
				return fmt.Errorf("failed to create temp file: %v", err)
			}
			defer os.Remove(tmp.Name())
			if err := arch.File.Save(tmp.Name()); err != nil {
				return fmt.Errorf("failed to save temp file: %v", err)
			}
			if err := tmp.Close(); err != nil {
				return fmt.Errorf("failed to close temp file: %v", err)
			}
			slices = append(slices, tmp.Name())
		}
		// write signed fat file
		if ff, err := macho.CreateFat(conf.Output, slices...); err != nil {
			return fmt.Errorf("failed to create fat file: %v", err)
		} else {
			defer ff.Close()
		}
	} else { // SINGLE MACHO ARCH
		if errors.Is(err, macho.ErrNotFat) {
			m, err := macho.Open(conf.Input)
			if err != nil {
				return err
			}
			defer m.Close()
			if err := m.CodeSign(conf.Codesign); err != nil {
				return fmt.Errorf("failed to codesign MachO file: %v", err)
			}
			// write signed file
			if err := m.Save(conf.Output); err != nil {
				return fmt.Errorf("failed to save signed MachO file: %v", err)
			}
		} else {
			return fmt.Errorf("failed to open MachO file: %v", err)
		}
	}

	return nil
}
