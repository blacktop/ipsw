package mpb

import (
	"io"
	"strings"
	"unicode/utf8"

	"github.com/vbauerster/mpb/v4/decor"
)

// SpinnerAlignment enum.
type SpinnerAlignment int

// SpinnerAlignment kinds.
const (
	SpinnerOnLeft SpinnerAlignment = iota
	SpinnerOnMiddle
	SpinnerOnRight
)

var defaultSpinnerStyle = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type spinnerFiller struct {
	frames    []string
	count     uint
	alignment SpinnerAlignment
}

// NewSpinnerFiller spinner Filler used with *Progress.AddSpinner
func NewSpinnerFiller(alignment SpinnerAlignment) Filler {
	filler := &spinnerFiller{
		frames:    defaultSpinnerStyle,
		alignment: alignment,
	}
	return filler
}

func (s *spinnerFiller) Fill(w io.Writer, width int, stat *decor.Statistics) {

	frame := s.frames[s.count%uint(len(s.frames))]
	frameWidth := utf8.RuneCountInString(frame)

	if width < frameWidth {
		return
	}

	switch rest := width - frameWidth; s.alignment {
	case SpinnerOnLeft:
		io.WriteString(w, frame+strings.Repeat(" ", rest))
	case SpinnerOnMiddle:
		str := strings.Repeat(" ", rest/2) + frame + strings.Repeat(" ", rest/2+rest%2)
		io.WriteString(w, str)
	case SpinnerOnRight:
		io.WriteString(w, strings.Repeat(" ", rest)+frame)
	}
	s.count++
}
