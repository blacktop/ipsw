//go:build !cgo

package sep

import "errors"

var ErrCGORequired = errors.New("sep parsing requires CGO; rebuild with CGO_ENABLED=1")

type Sep struct{}

func (Sep) String() string { return ErrCGORequired.Error() }

func Parse(string) (*Sep, error) { return nil, ErrCGORequired }
