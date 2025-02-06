package watch

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/blacktop/ipsw/internal/download"
)

func RunCommand(cmd string, commit download.Commit) error {
	env := os.Environ()
	env = append(env,
		fmt.Sprintf("IPSW_WATCH_OID=%s", commit.OID),
		fmt.Sprintf("IPSW_WATCH_URL=%s", commit.URL),
		fmt.Sprintf("IPSW_WATCH_AUTHOR=%s", commit.Author.Name),
		fmt.Sprintf("IPSW_WATCH_DATE=%s", commit.Author.Date),
		fmt.Sprintf("IPSW_WATCH_MESSAGE=%s", commit.Message),
	)
	c := exec.Command("sh", "-c", cmd)
	c.Env = env
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("failed to run command: %v", err)
	}
	return nil
}
