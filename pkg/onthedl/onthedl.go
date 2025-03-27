// Package onthedl is for downloading files in parallel
package onthedl

import (
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/apex/log"
)

// Download downloads a file from a URL to a filepath
func Download(filepath string, url string, chunkSize int) error {
	resp, err := http.Head(url)
	if err != nil {
		return err
	}

	fileSize, _ := strconv.Atoi(resp.Header.Get("Content-Length"))
	numChunks := fileSize / chunkSize
	if fileSize%chunkSize != 0 {
		numChunks++
	}

	var wg sync.WaitGroup
	wg.Add(numChunks)

	chunks := make([][]byte, numChunks)

	for i := range numChunks {
		go func(i int) {
			defer wg.Done()

			start := i * chunkSize
			end := min(start+chunkSize, fileSize)

			req, _ := http.NewRequest("GET", url, nil)
			req.Header.Add("Range", "bytes="+strconv.Itoa(start)+"-"+strconv.Itoa(end))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Errorf("Error downloading chunk %d: %v", i, err)
				return
			}
			defer resp.Body.Close()

			chunk, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Errorf("Error reading chunk %d: %v", i, err)
				return
			}
			chunks[i] = chunk
		}(i)
	}

	wg.Wait()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	for _, chunk := range chunks {
		if _, err := out.Write(chunk); err != nil {
			return err
		}
	}

	return nil
}
