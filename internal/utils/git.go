package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/go-git/go-git/v5"
	"github.com/sergi/go-diff/diffmatchpatch"
	"golang.org/x/sys/execabs"
	"golang.org/x/term"
)

// GitClone clones a git repo
func GitClone(repo, dst string) (string, error) {
	if _, err := execabs.LookPath("git"); err == nil {
		cmd := exec.Command("git", "clone", "--depth", "1", repo, dst)
		dat, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to clone repo '%s' to %s: %v", repo, dst, err)
		}
		return string(dat), nil
	} else { // use pure Go version of git
		if _, err := git.PlainClone(dst, false, &git.CloneOptions{
			URL:      repo,
			Depth:    1,
			Progress: os.Stderr,
		}); err != nil {
			return "", fmt.Errorf("failed to create local copy of 'appledb' repo: %v", err)
		}
		return "", nil
	}
}

// GitRefresh refreshes a git repo
func GitRefresh(repoPath string) (string, error) {
	if _, err := execabs.LookPath("git"); err == nil {
		cmd := exec.Command("git", "pull", "--rebase")
		cmd.Dir = repoPath
		dat, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("failed to refresh repo '%s': %v", repoPath, err)
		}
		return string(dat), nil
	} else { // use pure Go version of git
		r, err := git.PlainOpen(repoPath)
		if err != nil {
			return "", fmt.Errorf("failed to open local copy of 'appledb' repo: %v", err)
		}
		w, err := r.Worktree()
		if err != nil {
			return "", fmt.Errorf("failed to get worktree of local copy of 'appledb' repo: %v", err)
		}
		if err = w.Pull(&git.PullOptions{
			RemoteName: "origin",
			// Force:      true,
			Progress: os.Stderr,
		}); err != nil {
			if !errors.Is(err, git.NoErrAlreadyUpToDate) {
				return "", fmt.Errorf("failed to update local copy of 'appledb' repo: %v", err)
			}
		}
		return "", nil
	}
}

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

	if conf.Color {
		return dmp.DiffPrettyText(diffs), nil
	}
	var out strings.Builder
	for _, diff := range diffs {
		switch diff.Type {
		case diffmatchpatch.DiffDelete:
			fmt.Fprintf(&out, "[-%s-]", diff.Text)
		case diffmatchpatch.DiffInsert:
			fmt.Fprintf(&out, "{+%s+}", diff.Text)
		default:
			out.WriteString(diff.Text)
		}
	}
	return out.String(), nil
}

// createGitDiffPatch renders a unified diff by shelling out to the host git
// binary. The output bytes (hunk boundaries, context-line algorithm) depend on
// the installed git version. The diff cache (internal/diff) does not fold the
// git version into its cache scope, so a cache built on one host may render
// differently than a fresh run on a host with a different git; the cache is
// therefore host-bound by default. See machosJob.OptionsHash for details.
func createGitDiffPatch(src, dst string, conf *GitDiffConfig) (string, error) {
	tmpSrc, err := writeDiffInput("src", src)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpSrc)

	tmpDst, err := writeDiffInput("dst", dst)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpDst)

	out, err := runDiffTool(exec.Command("git", "diff", "--no-color", "--no-index", tmpSrc, tmpDst))
	if err != nil {
		return "", err
	}
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

// writeDiffInput writes content to a closed temp file for an external diff
// tool and returns its path. The caller removes the file.
func writeDiffInput(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	_, writeErr := f.WriteString(content)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write diff input %s: %w", f.Name(), err)
	}
	return f.Name(), nil
}

// runDiffTool returns the stdout of an external diff command. Diff tools exit 1
// when the inputs differ, so only other failures are errors.
func runDiffTool(cmd *exec.Cmd) (string, error) {
	out, err := cmd.Output()
	if err == nil {
		return string(out), nil
	}
	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		return "", fmt.Errorf("failed to run %s: %w", cmd.Args[0], err)
	}
	if exitErr.ExitCode() == 1 {
		return string(out), nil
	}
	return "", fmt.Errorf("%s failed: %w: %s", cmd.Args[0], err, strings.TrimSpace(string(exitErr.Stderr)))
}

func createDeltaDiffPatch(src, dst string, conf *GitDiffConfig) (string, error) {
	if !conf.Color {
		return createGoDiff(src, dst, conf)
	}

	tmpSrc, err := writeDiffInput("src", src)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpSrc)

	tmpDst, err := writeDiffInput("dst", dst)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpDst)

	width := 120
	if term.IsTerminal(0) {
		twidth, _, err := term.GetSize(0)
		if err != nil {
			return "", err
		}
		width = twidth
	}

	return runDiffTool(exec.Command(
		"delta",
		"--dark",
		"--diff-so-fancy",
		"--side-by-side",
		"--file-style", "omit",
		"--hunk-header-style", "omit",
		"--syntax-theme",
		"Nord",
		"--width", strconv.Itoa(width),
		tmpSrc,
		tmpDst,
	))
}

func ClangFormat(src, filename string, color bool) string {
	if _, err := exec.LookPath("clang-format"); err == nil {
		cmd := exec.Command(
			"clang-format",
			"-style={AlignConsecutiveDeclarations: true}",
			"--assume-filename",
			filename,
		)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return src
		}

		go func() {
			defer stdin.Close()
			io.WriteString(stdin, src)
		}()

		out, _ := cmd.CombinedOutput()
		// if err != nil {
		// 	return "", fmt.Errorf("clang-format failed %s: %v", out, err)
		// }

		src = string(out)
	}

	if color {
		b := new(strings.Builder)
		if err := quick.Highlight(b, src, "c", "terminal256", "nord"); err != nil {
			return ""
		}
		return b.String()
	}

	return src
}
