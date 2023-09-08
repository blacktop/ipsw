package utils

import (
	"encoding/base64"
	"fmt"
	"io"
)

// DisplayImageInTerminal displays an image in the terminal (supported in iTerm2 and VSCode)
func DisplayImageInTerminal(r io.Reader, size, width, height int) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read terminal image data: %w", err)
	}

	fmt.Print("\033]1337;")
	fmt.Print("File=inline=1")
	fmt.Printf(";size=%d", size)
	fmt.Printf(";width=%dpx", width)
	fmt.Printf(";height=%dpx", height)
	// fmt.Print(";preserveAspectRatio=1")
	// fmt.Print(";name=%s", base64.StdEncoding.EncodeToString([]byte(name)))
	fmt.Print(":")
	fmt.Printf("%s", base64.StdEncoding.EncodeToString(data))
	fmt.Print("\a\n")

	return nil
}
