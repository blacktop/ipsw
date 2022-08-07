package pipe

import (
	"errors"
	"strings"
)

// IsSkip returns true if the error is an ErrSkip.
func IsSkip(err error) bool {
	return errors.As(err, &ErrSkip{})
}

// ErrSkip occurs when a pipe is skipped for some reason.
type ErrSkip struct {
	reason string
}

// Error implements the error interface. returns the reason the pipe was skipped.
func (e ErrSkip) Error() string {
	return e.reason
}

// Skip skips this pipe with the given reason.
func Skip(reason string) ErrSkip {
	return ErrSkip{reason: reason}
}

// SkipMemento remembers previous skip errors so you can return them all at once later.
type SkipMemento struct {
	skips []string
}

// Remember a skip.
func (e *SkipMemento) Remember(err error) {
	for _, skip := range e.skips {
		if skip == err.Error() {
			return
		}
	}
	e.skips = append(e.skips, err.Error())
}

// Evaluate return a skip error with all previous skips, or nil if none happened.
func (e *SkipMemento) Evaluate() error {
	if len(e.skips) == 0 {
		return nil
	}
	return Skip(strings.Join(e.skips, ", "))
}
