package kernelcache

import (
	"archive/zip"
	"bufio"
	"bytes"
	"debug/macho"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing/iotest"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
	"github.com/blacktop/lzss"
	"github.com/pkg/errors"
)

// Img4 Kernelcache object
type Img4 struct {
	IM4P    string
	Name    string
	Version string
	Data    []byte
}

// A LzssHeader represents the LZSS header
type LzssHeader struct {
	CompressionType  uint32 // 0x636f6d70 "comp"
	Signature        uint32 // 0x6c7a7373 "lzss"
	CheckSum         uint32 // Likely CRC32
	UncompressedSize uint32
	CompressedSize   uint32
	Padding          [0x16c]byte
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Header LzssHeader
	Size   int
	Data   []byte
}

// Open opens the named file using os.Open and prepares it for use as a compressed kernelcache.
func Open(name string) (*CompressedCache, error) {
	log.Info("Parsing Compressed Kernelcache")

	content, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read Kernelcache")
	}

	var i Img4
	// NOTE: openssl asn1parse -i -inform DER -in kernelcache.iphone10
	if _, err := asn1.Unmarshal(content, &i); err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Kernelcache")
	}

	buffer := bytes.NewBuffer(i.Data)

	cc := CompressedCache{Size: buffer.Len()}

	// Read entire file header.
	if err := binary.Read(buffer, binary.BigEndian, &cc.Header); err != nil {
		return nil, err
	}

	msg := fmt.Sprintf("compressed size: %d, uncompressed: %d. checkSum: 0x%x",
		cc.Header.CompressedSize,
		cc.Header.UncompressedSize,
		cc.Header.CheckSum,
	)
	utils.Indent(log.Info)(msg)

	if int(cc.Header.CompressedSize) > cc.Size {
		return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, cc.Header.CompressedSize)
	}

	// Read compressed file data.
	cc.Data = buffer.Next(int(cc.Header.CompressedSize))

	return &cc, nil
}

// Extract extracts and decompresses a lernelcache from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting Kernelcache from IPSW")
	kcache, err := Unzip(ipsw, "")
	if err != nil {
		return errors.Wrap(err, "failed extract kernelcache from ipsw")
	}
	// defer os.Remove(kcache)

	kc, err := Open(kcache)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}

	log.Info("Decompressing Kernelcache")
	dec := lzss.Decompress(kc.Data)
	err = ioutil.WriteFile(kcache+".decompressed", dec[:kc.Header.UncompressedSize], 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	return nil
}

// Decompress decompresses a lernelcache
func Decompress(kcache string) error {
	kc, err := Open(kcache)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}
	// defer os.Remove(kcache)

	log.Info("Decompressing Kernelcache")
	dec := lzss.Decompress(kc.Data)
	err = ioutil.WriteFile(kcache+".decompressed", dec[:kc.Header.UncompressedSize], 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	return nil
}

// Unzip - https://stackoverflow.com/a/24792688
func Unzip(src, dest string) (string, error) {
	var kcacheName string
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := r.Close(); err != nil {
			panic(err)
		}
	}()

	os.MkdirAll(dest, 0755)

	// Closure to address file descriptors issue with all the deferred .Close() methods
	extractAndWriteFile := func(f *zip.File) error {
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func() {
			if err := rc.Close(); err != nil {
				panic(err)
			}
		}()

		path := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(path, f.Mode())
		} else {
			os.MkdirAll(filepath.Dir(path), f.Mode())
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
			if err != nil {
				return err
			}
			defer func() {
				if err := f.Close(); err != nil {
					panic(err)
				}
			}()

			_, err = io.Copy(f, rc)
			if err != nil {
				return err
			}
		}
		return nil
	}

	for _, f := range r.File {
		if strings.Contains(f.Name, "kernelcache") {
			kcacheName = path.Base(f.Name)
			err := extractAndWriteFile(f)
			if err != nil {
				return "", err
			}
		}
	}

	return kcacheName, nil
}

// ParseMachO parses the kernelcache as a mach-o
func ParseMachO(name string) error {
	f, err := macho.Open(name)
	if err != nil {
		return err
	}

	fmt.Println(f.FileHeader)

	err = os.Mkdir("diff", os.ModePerm)
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

						err = os.MkdirAll(filepath.Dir(filepath.Join("diff", filePath)), os.ModePerm)
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

	fileContent := ""
	for i, line := range lines {
		if i == index {
			fileContent += str
		}
		fileContent += line
		fileContent += "\n"
	}

	return ioutil.WriteFile(path, []byte(fileContent), 0644)
}
