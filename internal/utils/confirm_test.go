package utils

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
)

func TestConfirmOutcomes(t *testing.T) {
	for _, tt := range []struct {
		name        string
		auto        bool
		interactive bool
		answer      bool
		promptError error
		wantAnswer  bool
		wantError   bool
		wantPrompt  bool
	}{
		{name: "noninteractive", wantError: true},
		{name: "unattended confirmed", auto: true, wantAnswer: true},
		{name: "accepted", interactive: true, answer: true, wantAnswer: true, wantPrompt: true},
		{name: "declined", interactive: true, wantPrompt: true},
		{name: "EOF", interactive: true, promptError: io.EOF, wantError: true, wantPrompt: true},
		{name: "interrupted", interactive: true, promptError: terminal.InterruptErr, wantError: true, wantPrompt: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			prompted := false
			answer, err := confirm("Proceed?", tt.auto, tt.interactive, func(prompt *survey.Confirm, answer *bool) error {
				prompted = true
				if prompt.Message != "Proceed?" {
					t.Fatalf("unexpected prompt %q", prompt.Message)
				}
				*answer = tt.answer
				return tt.promptError
			})
			if answer != tt.wantAnswer || (err != nil) != tt.wantError || prompted != tt.wantPrompt {
				t.Fatalf("answer=%v err=%v prompted=%v", answer, err, prompted)
			}
			if err != nil && !strings.Contains(err.Error(), "--confirm") {
				t.Fatalf("missing unattended remedy: %v", err)
			}
			if tt.promptError != nil && !errors.Is(err, tt.promptError) {
				t.Fatalf("lost prompt error: %v", err)
			}
		})
	}
}
