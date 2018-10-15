package partialzip

import (
	"bufio"
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
)

// PartialZip defines a custom partialzip object
type PartialZip struct {
	URL   string
	Size  int64
	Files []*File
}

// New returns a newly created partialzip object.
func New(url string) (*PartialZip, error) {

	pz := &PartialZip{URL: url}

	err := pz.init()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read http response body")
	}

	return pz, nil
}

func (p *PartialZip) init() error {
	var client http.Client
	var chuck int64 = 10 * 1024

	// get remote zip size
	req, _ := http.NewRequest("HEAD", p.URL, nil)
	resp, _ := client.Do(req)
	p.Size = resp.ContentLength

	// pull chuck from end of remote zip
	reqRange := fmt.Sprintf("bytes=%d-%d", p.Size-chuck, p.Size)
	req, _ = http.NewRequest("GET", p.URL, nil)
	req.Header.Add("Range", reqRange)
	resp, _ = client.Do(req)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrap(err, "failed to read http response body")
	}
	defer resp.Body.Close()

	r := bytes.NewReader(body)

	// parse zip's directory end
	end, err := readDirectoryEnd(r, chuck)
	if err != nil {
		return errors.Wrap(err, "failed to read directory end from remote zip")
	}

	// z.r = r
	p.Files = make([]*File, 0, end.directoryRecords)
	// z.Comment = end.comment
	rs := io.NewSectionReader(r, 0, chuck)

	offset := int64(chuck - (p.Size - int64(end.directoryOffset)))
	if _, err = rs.Seek(offset, io.SeekStart); err != nil {
		return errors.Wrap(err, "failed to seek to begining of directory")
	}
	buf := bufio.NewReader(rs)

	// The count of files inside a zip is truncated to fit in a uint16.
	// Gloss over this by reading headers until we encounter
	// a bad one, and then only report an ErrFormat or UnexpectedEOF if
	// the file count modulo 65536 is incorrect.
	for {
		f := &File{zipr: r, zipsize: p.Size}
		err = readDirectoryHeader(f, buf)
		if err == errFormat || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "failed to read directory header")
		}
		p.Files = append(p.Files, f)
	}
	if uint16(len(p.Files)) != uint16(end.directoryRecords) { // only compare 16 bits here
		// Return the readDirectoryHeader error if we read
		// the wrong number of directory entries.
		return errors.Wrap(err, "failed to parse all files listed in directory end")
	}

	return nil
}

// List lists the files in the remote zip.
// It returns a string array of file paths.
func (p *PartialZip) List() []string {
	filePaths := []string{}

	for _, file := range p.Files {
		filePaths = append(filePaths, file.Name)
	}

	return filePaths
}

// Get gets a handle to a file from the remote zip.
// It returns an io.ReadCloser and an error, if any.
func (p *PartialZip) Get(path string) (io.ReadCloser, error) {

	var client http.Client
	var padding uint64 = 1024

	for _, file := range p.Files {
		// find path in zip directory
		if strings.EqualFold(file.Name, path) {
			req, _ := http.NewRequest("GET", p.URL, nil)
			end := uint64(file.headerOffset) + file.CompressedSize64 + padding
			reqRange := fmt.Sprintf("bytes=%d-%d", file.headerOffset, end)
			req.Header.Add("Range", reqRange)
			resp, _ := client.Do(req)

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return nil, errors.Wrap(err, "failed to read http response body")
			}

			dataOffset, err := findBodyOffset(bytes.NewReader(body))
			if err != nil {
				return nil, errors.Wrap(err, "failed to find data start offset in zip file header")
			}

			return flate.NewReader(bytes.NewReader(body[dataOffset : uint64(len(body))-padding+dataOffset])), nil
		}
	}

	return nil, fmt.Errorf("file %s does not exist in remote zip", path)
}

// Download downloads a file from the remote zip.
// It returns the number of bytes written and an error, if any.
func (p *PartialZip) Download(path string) (int, error) {

	var client http.Client
	var padding uint64 = 1024
	var n int

	for _, file := range p.Files {
		// find path in zip directory
		if strings.EqualFold(file.Name, path) {
			req, _ := http.NewRequest("GET", p.URL, nil)
			end := uint64(file.headerOffset) + file.CompressedSize64 + padding
			reqRange := fmt.Sprintf("bytes=%d-%d", file.headerOffset, end)
			req.Header.Add("Range", reqRange)
			resp, _ := client.Do(req)

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return n, errors.Wrap(err, "failed to read http response body")
			}

			dataOffset, err := findBodyOffset(bytes.NewReader(body))
			if err != nil {
				return n, errors.Wrap(err, "failed to find data start offset in zip file header")
			}

			enflated, err := ioutil.ReadAll(flate.NewReader(bytes.NewReader(body[dataOffset : uint64(len(body))-padding+dataOffset])))
			if err != nil {
				return n, errors.Wrap(err, "failed to flate decompress data")
			}

			of, err := os.Create(path)
			defer of.Close()

			n, err = of.Write(enflated)
			if err != nil {
				return n, errors.Wrap(err, "failed to write decompressed data to file")
			}
		}
	}

	return n, nil
}
