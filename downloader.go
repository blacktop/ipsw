package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vbauerster/mpb"
	"github.com/vbauerster/mpb/decor"
)

// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory. We pass an io.TeeReader
// into Copy() to report progress on the download.
func DownloadFile(url string) error {

	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server return status: %s", resp.Status)
	}

	size := resp.ContentLength

	// create dest
	destName := filepath.Base(url)
	dest, err := os.Create(destName)
	if err != nil {
		return errors.Wrapf(err, "cannot create %s", destName)
	}
	defer dest.Close()

	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithFormat("[=>-|"),
		mpb.WithRefreshRate(180*time.Millisecond),
	)

	bar := p.AddBar(size,
		mpb.PrependDecorators(
			decor.CountersKibiByte("% 6.1f / % 6.1f"),
		),
		mpb.AppendDecorators(
			decor.EwmaETA(decor.ET_STYLE_MMSS, float64(size)/2048),
			decor.Name(" ] "),
			decor.AverageSpeed(decor.UnitKiB, "% .2f"),
		),
	)

	// create proxy reader
	reader := bar.ProxyReader(resp.Body)

	// and copy from reader, ignoring errors
	io.Copy(dest, reader)

	p.Wait()

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
