package kernelcache

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing/iotest"

	"github.com/blacktop/go-macho"
)

// ParseMachO parses the kernelcache as a mach-o
func ParseMachO(name string) error {
	f, err := macho.Open(name)
	if err != nil {
		return err
	}

	fmt.Println(f.FileHeader)

	err = os.Mkdir("diff", 0750)
	if err != nil {
		return err
	}

	for _, sec := range f.Sections {
		if strings.EqualFold(sec.Name, "__cstring") && strings.EqualFold(sec.Seg, "__TEXT") {
			r := bufio.NewReader(sec.Open())
			for {
				s, err := r.ReadString('\x00')
				if err == io.EOF {
					break
				}

				if err != nil && err != iotest.ErrTimeout {
					panic("GetLines: " + err.Error())
				}

				if strings.Contains(s, "@/BuildRoot/") {
					var assertStr string
					parts := strings.Split(strings.TrimSpace(s), "@/BuildRoot/")
					if len(parts) > 1 {
						assertStr = parts[0]
						fileAndLineNum := parts[1]
						parts = strings.Split(fileAndLineNum, ":")
					} else {
						fmt.Println("WHAT?? ", s)
					}
					if len(parts) > 1 {
						filePath := parts[0]
						lineNum := parts[1]
						fmt.Printf("%s on line %s ==> %s\n", filePath, lineNum, assertStr)

						err = os.MkdirAll(filepath.Dir(filepath.Join("diff", filePath)), 0750)
						if err != nil {
							return err
						}

						f, err := os.Create(filepath.Join("diff", filePath))
						if err != nil {
							return err
						}
						f.Close()
					} else {
						fmt.Println("WHAT?? ", s)
					}
				}
			}
		}
	}

	return nil
}

func File2lines(filePath string) ([]string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LinesFromReader(f)
}

func LinesFromReader(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// InsertStringToFile inserts sting to n-th line of file.
// If you want to insert a line, append newline '\n' to the end of the string.
func InsertStringToFile(path, str string, index int) error {
	lines, err := File2lines(path)
	if err != nil {
		return err
	}

	var fileContent strings.Builder
	for i, line := range lines {
		if i == index {
			fileContent.WriteString(str)
		}
		fileContent.WriteString(line)
		fileContent.WriteString("\n")
	}

	return os.WriteFile(path, []byte(fileContent.String()), 0660)
}
