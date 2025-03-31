package git

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/shurcooL/githubv4"
)

// GetFunctionRegex returns a regex pattern to match functions based on file extension
func GetFunctionRegex(funcName, filePath string) *regexp.Regexp {
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".go":
		// Go function pattern - anchored to the 'func' keyword
		return regexp.MustCompile(fmt.Sprintf(`(?m)^func\s+(\(\s*\w+\s+[^)]+\)\s+)?%s\s*\([^)]*\)[^{]*{[\s\S]*?^}`, funcName))
	case ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx":
		// C/C++ function pattern - anchored to the function name
		return regexp.MustCompile(fmt.Sprintf(`(?m)^[^\n;{}]*%s\s*\([^)]*\)\s*(?:{[\s\S]*?^}|;)`, funcName))
	case ".js", ".ts":
		// JavaScript/TypeScript pattern - anchored to various function forms
		return regexp.MustCompile(fmt.Sprintf(`(?m)^(?:function\s+%s|const\s+%s\s*=\s*function|const\s+%s\s*=\s*\([^)]*\)\s*=>|let\s+%s\s*=\s*function|var\s+%s\s*=\s*function|%s\s*:\s*function)\s*\([^)]*\)[^{]*{[\s\S]*?^}`,
			funcName, funcName, funcName, funcName, funcName, funcName))
	case ".py":
		// Python function pattern - anchored to the def keyword
		return regexp.MustCompile(fmt.Sprintf(`(?m)^def\s+%s\s*\([^)]*\)[^:]*:[\s\S]*?^(?:\S|$)`, funcName))
	case ".java", ".kt", ".swift":
		// Java/Kotlin/Swift pattern - anchored to function with proper indentation
		return regexp.MustCompile(fmt.Sprintf(`(?m)^[^\n;{}]*\s+%s\s*\([^)]*\)[^{]*{[\s\S]*?^}`, funcName))
	case ".rb":
		// Ruby pattern - anchored to the def keyword
		return regexp.MustCompile(fmt.Sprintf(`(?m)^def\s+%s(?:\s*\([^)]*\)|\s+[^(\n]*|\s*)\n[\s\S]*?^end`, funcName))
	case ".php":
		// PHP pattern - anchored to the function keyword
		return regexp.MustCompile(fmt.Sprintf(`(?m)^function\s+%s\s*\([^)]*\)[^{]*{[\s\S]*?^}`, funcName))
	default:
		// Generic pattern - anchored to function name with word boundary
		return regexp.MustCompile(fmt.Sprintf(`(?m)^\b%s\b\s*\([^)]*\)[^{]*{[\s\S]*?^}`, funcName))
	}
}

type GitFunctionChange struct {
	Commit  *download.Commit
	Content string
}

// GetFunctionChanges returns a history of changes to a specific function in a file
func GetFunctionChanges(repo *git.Repository, funcName, filePath string) ([]GitFunctionChange, error) {
	var changes []GitFunctionChange

	// Get commit history
	iter, err := repo.Log(&git.LogOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get commit history: %v", err)
	}
	defer iter.Close()

	var commits []*object.Commit
	if err := iter.ForEach(func(c *object.Commit) error {
		commits = append(commits, c)
		return nil
	}); err != nil {
		log.Debugf("Some commits could not be processed: %v", err)
		if len(commits) == 0 {
			return nil, fmt.Errorf("failed to iterate commits: %v", err)
		}
		// Continue with the commits we were able to get
	}

	if len(commits) == 0 {
		return nil, fmt.Errorf("no commits found in repository")
	}

	// Create pattern based on file type
	functionRegex := GetFunctionRegex(funcName, filePath)
	if functionRegex == nil {
		return nil, fmt.Errorf("could not generate function regex for file type: %s", filepath.Ext(filePath))
	}

	// Collect all function versions
	type funcVersion struct {
		commit  *object.Commit
		content string
	}
	var funcVersions []funcVersion

	for _, commit := range commits {
		// Get file content at this commit
		file, err := commit.File(filePath)
		if err != nil {
			continue
		}

		content, err := file.Contents()
		if err != nil {
			log.Warnf("Failed to get contents of %s at commit %s: %v", filePath, commit.Hash, err)
			continue
		}

		// Extract the function content
		matches := functionRegex.FindStringSubmatch(content)
		var currentContent string
		if len(matches) > 0 {
			currentContent = matches[0]
		} else {
			currentContent = ""
		}

		// Add to our versions list (even if empty, to track deletions)
		funcVersions = append(funcVersions, funcVersion{
			commit:  commit,
			content: currentContent,
		})
	}

	if len(funcVersions) == 0 {
		_, err = commits[0].File(filePath)
		if err != nil {
			return nil, fmt.Errorf("file '%s' not found in commit history", filePath)
		}
		return nil, fmt.Errorf("function '%s' not found in file '%s' across history", funcName, filePath)
	}

	// Build the changes list, comparing adjacent versions
	var functionFoundInHistory bool
	for i := range funcVersions {
		current := funcVersions[i]
		previousContent := ""
		if i+1 < len(funcVersions) {
			previousContent = funcVersions[i+1].content
		}

		if current.content != "" {
			functionFoundInHistory = true
		}

		isChange := i < len(funcVersions)-1 && previousContent != current.content && current.content != ""

		if isChange {
			headline := strings.SplitN(current.commit.Message, "\n", 2)[0]
			body := ""
			if strings.Contains(current.commit.Message, "\n") {
				body = strings.SplitN(current.commit.Message, "\n", 2)[1]
			}
			commitInfo := &download.Commit{
				OID: githubv4.GitObjectID(current.commit.Hash.String()),
				Author: struct {
					Name  githubv4.String       `json:"name,omitempty"`
					Email githubv4.String       `json:"email,omitempty"`
					Date  githubv4.GitTimestamp `json:"date"`
				}{
					Name:  githubv4.String(current.commit.Author.Name),
					Email: githubv4.String(current.commit.Author.Email),
					Date:  githubv4.GitTimestamp{Time: current.commit.Author.When},
				},
				Message:     githubv4.String(current.commit.Message),
				MsgHeadline: githubv4.String(headline),
				MsgBody:     githubv4.String(body),
			}

			changes = append(changes, GitFunctionChange{
				Commit:  commitInfo,
				Content: current.content,
			})
		}
	}

	if !functionFoundInHistory && len(changes) == 0 {
		return nil, fmt.Errorf("function '%s' not found in file '%s' across history", funcName, filePath)
	}

	return changes, nil
}
