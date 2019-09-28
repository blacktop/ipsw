package dyld

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// GetWebKitVersion greps the dyld_shared_cache for the WebKit version string
func GetWebKitVersion(path string) (string, error) {

	fd, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fd.Close()

	var re = regexp.MustCompile(`WebKit2-(\d+\.)?(\d+\.)?(\d+\.)?(\d+\.)(\*|\d+)`)
	var match string

	reader := bufio.NewReader(fd)

	line, err := reader.ReadString('\n')
	for err == nil {
		match = re.FindString(line)
		if len(match) > 0 {
			break
		}
		line, err = reader.ReadString('\n')
	}

	if err == io.EOF {
		return match, nil
	}

	if len(match) > 0 {
		return strings.TrimPrefix(match, "WebKit2-")[1:], nil
	}
	// TODO: crawl https://trac.webkit.org/browser/webkit/branches?order=date

	return "", fmt.Errorf("unable to find WebKit version in file: %s", path)
}
