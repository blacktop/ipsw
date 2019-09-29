package api

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/utils"
	"github.com/gofrs/flock"
	"github.com/pkg/errors"
	"github.com/vbauerster/mpb/v4"
	"github.com/vbauerster/mpb/v4/decor"
)

const ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13 Safari/605.1.15"

// Download is a downloader object
type Download struct {
	URL  string
	Sha1 string

	size         int64
	bytesResumed int64
	canResume    bool
	resume       bool

	client *http.Client
}

// NewDownload creates a new downloader
func NewDownload(url, sha1, proxy string, insecure bool) *Download {
	return &Download{
		URL:  url,
		Sha1: sha1,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:           getProxy(proxy),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		},
	}
}

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

func (d *Download) getHEAD() error {

	req, err := http.NewRequest("HEAD", d.URL, nil)
	if err != nil {
		return errors.Wrap(err, "cannot create http request")
	}
	req.Header.Add("User-Agent", ua)

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	d.size = resp.ContentLength

	if resp.Header.Get("Accept-Ranges") == "bytes" {
		d.canResume = true
	}

	return nil
}

// Do will download a url to a local file. It's efficient because it will
// write as it downloads and not load the whole file into memory. We pass an io.TeeReader
// into Copy() to report progress on the download.
func (d *Download) Do() error {

	d.getHEAD()

	req, err := http.NewRequest("GET", d.URL, nil)
	if err != nil {
		return errors.Wrap(err, "cannot create http request")
	}
	req.Header.Add("User-Agent", ua)

	// check for a completed download
	destName := strings.Replace(path.Base(d.URL), ",", "_", -1)
	if _, err := os.Stat(destName); !os.IsNotExist(err) {
		utils.Indent(log.Warn, 2)(fmt.Sprintf("ipsw already exists: %s", destName))
		return nil
	}

	if d.canResume {
		if f, err := os.Stat(destName + ".download"); !os.IsNotExist(err) {
			d.resume = true
			d.bytesResumed = f.Size()
			rangeHeader := fmt.Sprintf("bytes=%d-", d.bytesResumed)
			utils.Indent(log.WithField("range", rangeHeader).Debug, 2)("Setting Header")
			req.Header.Add("Range", rangeHeader)
		}
	}

	utils.Indent(log.WithField("file", destName).Debug, 2)("Downloading")
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("server return status: %s", resp.Status)
	}

	fileLock := flock.New(destName + ".download")
	defer fileLock.Unlock()

	locked, err := fileLock.TryLock()
	if err != nil {
		return errors.Wrapf(err, "unable to lock %s", destName+".download")
	}

	if !locked {
		log.Errorf("%s is being downloaded by another instance", destName+".download")
		return nil
	}

	var dest *os.File
	if d.resume {
		utils.Indent(log.WithField("file", destName).Warn, 2)("Resuming a previous download")
		dest, err = os.OpenFile(destName+".download", os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return errors.Wrapf(err, "cannot create %s", destName)
		}
		defer dest.Close()
		dest.Seek(0, os.SEEK_END)
	} else {
		dest, err = os.Create(destName + ".download")
		if err != nil {
			return errors.Wrapf(err, "cannot create %s", destName)
		}
		defer dest.Close()
	}

	p := mpb.New(
		mpb.WithWidth(60),
		mpb.WithRefreshRate(180*time.Millisecond),
	)

	bar := p.AddBar(d.size, mpb.BarStyle("[=>-|"),
		mpb.PrependDecorators(
			decor.CountersKibiByte("\t% 6.1f / % 6.1f"),
		),
		mpb.AppendDecorators(
			decor.EwmaETA(decor.ET_STYLE_GO, float64(d.size)/2048),
			decor.Name(" ] "),
			decor.OnComplete(decor.Spinner(nil), "✅"),
			decor.EwmaSpeed(decor.UnitKiB, "% .2f", (float64(d.size)/2048), decor.WCSyncSpace),
		),
	)

	if d.resume {
		// bar.SetCurrent(d.bytesResumed)
		bar.SetRefill(d.bytesResumed)
		bar.IncrInt64(d.bytesResumed)
	}

	// create proxy reader
	reader := bar.ProxyReader(resp.Body)
	defer reader.Close()

	if d.resume {
		if _, err := io.Copy(dest, reader); err != nil {
			return err
		}

		p.Wait()

		utils.Indent(log.Info, 2)("verifying sha1sum...")
		if ok, _ := utils.Verify(d.Sha1, destName+".download"); !ok {
			if err := os.Remove(destName + ".download"); err != nil {
				return errors.Wrap(err, "cannot remove downloaded file with checksum mismatch")
			}
			return fmt.Errorf("bad download: ipsw %s sha1 hash is incorrect", destName+".download")
		}

	} else {
		tee := io.TeeReader(reader, dest)

		h := sha1.New()
		if _, err := io.Copy(h, tee); err != nil {
			return err
		}

		p.Wait()

		utils.Indent(log.Info, 2)("verifying sha1sum...")
		checksum, _ := hex.DecodeString(d.Sha1)

		if !bytes.Equal(h.Sum(nil), checksum) {
			utils.Indent(log.WithFields(log.Fields{
				"expected": d.Sha1,
				"actual":   fmt.Sprintf("%x", h.Sum(nil)),
			}).Error, 3)("❌ BAD CHECKSUM")
			if err := os.Remove(destName); err != nil {
				return errors.Wrap(err, "cannot remove downloaded file with checksum mismatch")
			}
		}
	}

	err = os.Rename(destName+".download", destName)
	if err != nil {
		return errors.Wrap(err, "failed to remove .download from completed download")
	}

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
