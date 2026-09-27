package utils

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"golang.org/x/term"
)

// Confirm returns false without an error only when the user explicitly declines.
// autoConfirm permits unattended use; otherwise both input and output need a TTY.
func Confirm(message string, autoConfirm bool) (bool, error) {
	return confirm(message, autoConfirm,
		term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd())),
		func(prompt *survey.Confirm, answer *bool) error { return survey.AskOne(prompt, answer) })
}

func confirm(message string, autoConfirm, interactive bool, ask func(*survey.Confirm, *bool) error) (bool, error) {
	if autoConfirm {
		return true, nil
	}
	if !interactive {
		return false, fmt.Errorf("confirmation requires an interactive terminal; use --confirm to proceed unattended")
	}
	var answer bool
	if err := ask(&survey.Confirm{Message: message}, &answer); err != nil {
		return false, fmt.Errorf("confirmation failed (use --confirm to proceed unattended): %w", err)
	}
	return answer, nil
}
