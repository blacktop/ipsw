package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	humanize "github.com/dustin/go-humanize"
)

// WriteCounter counts the number of bytes written to it. It implements to the io.Writer
// interface and we can pass this into io.TeeReader() which will report progress on each
// write cycle.
type WriteCounter struct {
	Total uint64
}

func (wc *WriteCounter) Write(p []byte) (int, error) {
	n := len(p)
	wc.Total += uint64(n)
	wc.PrintProgress()
	return n, nil
}

// PrintProgress prints download progress
func (wc WriteCounter) PrintProgress() {
	// Clear the line by using a character return to go back to the start and remove
	// the remaining characters by filling it with spaces
	fmt.Printf("\r%s", strings.Repeat(" ", 35))

	// Return again and print current status of download
	// We use the humanize package to print the bytes in a meaningful way (e.g. 10 MB)
	fmt.Printf("\rDownloading... %s complete", humanize.Bytes(wc.Total))
}

// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory. We pass an io.TeeReader
// into Copy() to report progress on the download.
func DownloadFile(filepath string, url string) error {

	// Create the file, but give it a tmp file extension, this means we won't overwrite a
	// file until it's downloaded, but we'll remove the tmp extension once downloaded.
	out, err := os.Create(filepath + ".tmp")
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create our progress reporter and pass it to be used alongside our writer
	counter := &WriteCounter{}
	_, err = io.Copy(out, io.TeeReader(resp.Body, counter))
	if err != nil {
		return err
	}

	// The progress use the same line so print a new line once it's finished downloading
	fmt.Print("\n")

	err = os.Rename(filepath+".tmp", filepath)
	if err != nil {
		return err
	}

	return nil
}

// Unzip - https://stackoverflow.com/a/24792688
func Unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
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
			err := extractAndWriteFile(f)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func multiDownload() error {
	// 	res, _ := http.Head("http://localhost/rand.txt") // 187 MB file of random numbers per line
	// 	maps := res.Header
	// 	length, _ := strconv.Atoi(maps["Content-Length"][0]) // Get the content length from the header request
	// 	limit := 10                                          // 10 Go-routines for the process so each downloads 18.7MB
	// 	len_sub := length / limit                            // Bytes for each Go-routine
	// 	diff := length % limit                               // Get the remaining for the last request
	// 	body := make([]string, 11)                           // Make up a temporary array to hold the data to be written to the file
	// 	for i := 0; i < limit; i++ {
	// 		wg.Add(1)

	// 		min := len_sub * i       // Min range
	// 		max := len_sub * (i + 1) // Max range

	// 		if i == limit-1 {
	// 			max += diff // Add the remaining bytes in the last request
	// 		}

	// 		go func(min int, max int, i int) {
	// 			client := &http.Client{}
	// 			req, _ := http.NewRequest("GET", "http://localhost/rand.txt", nil)
	// 			range_header := "bytes=" + strconv.Itoa(min) + "-" + strconv.Itoa(max-1) // Add the data for the Range header of the form "bytes=0-100"
	// 			req.Header.Add("Range", range_header)
	// 			resp, _ := client.Do(req)
	// 			defer resp.Body.Close()
	// 			reader, _ := ioutil.ReadAll(resp.Body)
	// 			body[i] = string(reader)
	// 			ioutil.WriteFile(strconv.Itoa(i), []byte(string(body[i])), 0x777) // Write to the file i as a byte array
	// 			wg.Done()
	// 			//          ioutil.WriteFile("new_oct.png", []byte(string(body)), 0x777)
	// 		}(min, max, i)
	// 	}
	// 	wg.Wait()
	return nil
}
