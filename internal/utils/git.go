package utils

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/sergi/go-diff/diffmatchpatch"
	"golang.org/x/term"
)

type GitDiffConfig struct {
	Tool  string
	Color bool
}

func GitDiff(src, dst string, conf *GitDiffConfig) (string, error) {
	switch conf.Tool {
	case "delta":
		return createDeltaDiffPatch(src, dst, conf)
	case "git":
		return createGitDiffPatch(src, dst, conf)
	case "go":
		return createGoDiff(src, dst, conf)
	default:
		if _, err := exec.LookPath("delta"); err == nil {
			return createDeltaDiffPatch(src, dst, conf)
		} else if _, err := exec.LookPath("git"); err == nil {
			return createGitDiffPatch(src, dst, conf)
		}
		return createGoDiff(src, dst, conf)
	}
}

func createGoDiff(src, dst string, conf *GitDiffConfig) (string, error) {
	dmp := diffmatchpatch.New()

	diffs := dmp.DiffMain(src, dst, false)
	if len(diffs) > 2 {
		diffs = dmp.DiffCleanupSemanticLossless(diffs)
		diffs = dmp.DiffCleanupEfficiency(diffs)
	}

	if len(diffs) == 1 {
		if diffs[0].Type == diffmatchpatch.DiffEqual {
			return "", nil
		}
	}

	return dmp.DiffPrettyText(diffs), nil
}

func createGitDiffPatch(src, dst string, conf *GitDiffConfig) (string, error) {
	tmpSrc, err := os.CreateTemp("", "src")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpSrc.Name())

	os.WriteFile(tmpSrc.Name(), []byte(src), 0644)

	tmpDst, err := os.CreateTemp("", "dst")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpDst.Name())

	os.WriteFile(tmpDst.Name(), []byte(dst), 0644)

	cmd := exec.Command("git", "diff", "--no-index", tmpSrc.Name(), tmpDst.Name())

	dat, _ := cmd.CombinedOutput()

	out := string(dat)
	// strip the first 4 lines of the patch file
	_, out, _ = strings.Cut(out, "\n")
	_, out, _ = strings.Cut(out, "\n")
	_, out, _ = strings.Cut(out, "\n")
	_, out, _ = strings.Cut(out, "\n")
	// strip the @@ gap lines
	re := regexp.MustCompile("(?m)^@@ .*$")
	out = re.ReplaceAllString(out, "")
	if conf.Color {
		// colorize the diff
		b := new(strings.Builder)
		if err := quick.Highlight(b, out, "diff", "terminal256", "nord"); err != nil {
			return "", err
		}
		return b.String(), nil
	}
	return out, nil
}

func createDeltaDiffPatch(src, dst string, conf *GitDiffConfig) (string, error) {
	tmpSrc, err := os.CreateTemp("", "src")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpSrc.Name())

	os.WriteFile(tmpSrc.Name(), []byte(src), 0644)

	tmpDst, err := os.CreateTemp("", "dst")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpDst.Name())

	os.WriteFile(tmpDst.Name(), []byte(dst), 0644)

	width := 120
	if term.IsTerminal(0) {
		twidth, _, err := term.GetSize(0)
		if err != nil {
			return "", err
		}
		width = twidth
	}

	cmd := exec.Command(
		"delta",
		"--dark",
		"--diff-so-fancy",
		"--side-by-side",
		"--file-style", "omit",
		"--hunk-header-style", "omit",
		"--syntax-theme",
		"Nord",
		"--width", strconv.Itoa(width),
		tmpSrc.Name(),
		tmpDst.Name(),
	)

	out, _ := cmd.CombinedOutput()
	// if err != nil {
	// 	return "", fmt.Errorf("delta failed %s: %v", out, err)
	// }

	return string(out), nil
}
