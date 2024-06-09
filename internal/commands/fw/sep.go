package fw

import (
	"github.com/blacktop/ipsw/pkg/sep"
)

func SplitSepFW(in, folder string) ([]string, error) {
	var out []string

	sp, err := sep.Parse(in)
	if err != nil {
		return nil, err
	}

	_ = sp

	// FIXME: implement sep split
	panic("not implemented")

	return out, nil
}
