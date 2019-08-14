package api

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/pkg/errors"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

func getProxy(proxy string) func(*http.Request) (*url.URL, error) {
	if len(proxy) > 0 {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.WithError(err).Error("bad proxy url")
		}
		return http.ProxyURL(proxyURL)
	}
	return http.ProxyFromEnvironment
}

// DownloadFile will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory. We pass an io.TeeReader
// into Copy() to report progress on the download.
func DownloadFile(url, proxy string, insecure bool) error {

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           getProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "cannot create http request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server return status: %s", resp.Status)
	}

	size := resp.ContentLength

	// create dest
	destName := filepath.Base(url)
	// remove commas
	destName = strings.Replace(destName, ",", "_", -1)
	dest, err := os.Create(destName)
	if err != nil {
		return errors.Wrapf(err, "cannot create %s", destName)
	}
	defer dest.Close()

	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithRefreshRate(180*time.Millisecond),
	)

	bar := p.AddBar(size, mpb.BarStyle("[=>-|"),
		mpb.PrependDecorators(
			decor.CountersKibiByte("\t% 6.1f / % 6.1f"),
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

// func multiDownload(urls []string, proxy string, insecure bool) {
// 	var wg sync.WaitGroup
// 	// pass &wg (optional), so p will wait for it eventually
// 	p := mpb.New(mpb.WithWaitGroup(&wg))
// 	total, numBars := 100, 3
// 	wg.Add(numBars)

// 	for i := 0; i < numBars; i++ {
// 		name := fmt.Sprintf("Bar#%d:", i)
// 		bar := p.AddBar(int64(total),
// 			mpb.PrependDecorators(
// 				// simple name decorator
// 				decor.Name(name),
// 				// decor.DSyncWidth bit enables column width synchronization
// 				decor.Percentage(decor.WCSyncSpace),
// 			),
// 			mpb.AppendDecorators(
// 				// replace ETA decorator with "done" message, OnComplete event
// 				decor.OnComplete(
// 					// ETA decorator with ewma age of 60
// 					decor.EwmaETA(decor.ET_STYLE_GO, 60), "done",
// 				),
// 			),
// 		)
// 		// download an ipsw
// 		go func(url, proxy string, insecure bool) {
// 			defer wg.Done()
// 			client := &http.Client{
// 				Transport: &http.Transport{
// 					Proxy:           getProxy(proxy),
// 					TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
// 				},
// 			}

// 			req, err := http.NewRequest("GET", url, nil)
// 			if err != nil {
// 				return errors.Wrap(err, "cannot create http request")
// 			}

// 			resp, err := client.Do(req)
// 			if err != nil {
// 				return err
// 			}
// 			defer resp.Body.Close()

// 			if resp.StatusCode != http.StatusOK {
// 				return fmt.Errorf("server return status: %s", resp.Status)
// 			}

// 			size := resp.ContentLength

// 			// create dest
// 			destName := filepath.Base(url)
// 			dest, err := os.Create(destName)
// 			if err != nil {
// 				return errors.Wrapf(err, "cannot create %s", destName)
// 			}
// 			defer dest.Close()
// 		}(url, proxy, insecure)
// 	}
// 	// Waiting for passed &wg and for all bars to complete and flush
// 	p.Wait()
// }

// func newTask(wg *sync.WaitGroup, b *mpb.Bar, incrBy int) {
// 	defer wg.Done()
// 	max := 100 * time.Millisecond
// 	for !b.Completed() {
// 		start := time.Now()
// 		time.Sleep(time.Duration(rand.Intn(10)+1) * max / 10)
// 		// ewma based decorators require work duration measurement
// 		b.IncrBy(incrBy, time.Since(start))
// 	}
// }
