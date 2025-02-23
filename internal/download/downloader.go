package download

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	// "github.com/gofrs/flock"
	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/net/http/httpproxy"
)

// Download is a downloader object
type Download struct {
	URL      string
	Sha1     string
	DestName string
	Headers  map[string]string

	size         int64
	bytesResumed int64
	resume       bool
	canResume    bool
	skipAll      bool
	resumeAll    bool
	restartAll   bool
	ignoreSha1   bool
	verbose      bool

	client *http.Client
}

type geoQuery struct {
	Query       string `json:"query,omitempty"`
	Status      string `json:"status,omitempty"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Region      string `json:"region,omitempty"`
	RegionName  string `json:"region_name,omitempty"`
	City        string `json:"city,omitempty"`
	Zip         string `json:"zip,omitempty"`
	Lat         string `json:"lat,omitempty"`
	Lon         string `json:"lon,omitempty"`
	Timezone    string `json:"timezone,omitempty"`
	Isp         string `json:"isp,omitempty"`
	Org         string `json:"org,omitempty"`
	As          string `json:"as,omitempty"`
}

// NewDownload creates a new downloader
func NewDownload(proxy string, insecure, skipAll, resumeAll, restartAll, ignoreSha1, verbose bool) *Download {
	return &Download{
		// URL:     url,
		// Sha1:    sha1,
		resume:     false,
		skipAll:    skipAll,
		resumeAll:  resumeAll,
		restartAll: restartAll,
		ignoreSha1: ignoreSha1,
		verbose:    verbose,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy:           GetProxy(proxy),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
				// MaxConnsPerHost:   50,
				ForceAttemptHTTP2: true,
			},
		},
	}
}

// GetProxy takes either an input string or read the enviornment and returns a proxy function
func GetProxy(proxy string) func(*http.Request) (*url.URL, error) {
	if len(proxy) > 0 {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.WithError(err).Error("bad proxy url")
		}
		log.Debugf("proxy set to: %s", proxyURL)

		return http.ProxyURL(proxyURL)
	}

	conf := httpproxy.FromEnvironment()
	if len(conf.HTTPProxy) > 0 || len(conf.HTTPSProxy) > 0 {
		log.WithFields(log.Fields{
			"http_proxy":  conf.HTTPProxy,
			"https_proxy": conf.HTTPSProxy,
			"no_proxy":    conf.NoProxy,
		}).Debugf("proxy info from environment")
	}

	return http.ProxyFromEnvironment
}

func (d *Download) getHEAD() error {

	req, err := http.NewRequest("HEAD", d.URL, nil)
	if err != nil {
		return errors.Wrap(err, "cannot create http request")
	}
	req.Header.Add("User-Agent", utils.RandomAgent())

	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.ContentLength < 0 {
		return fmt.Errorf("content length is not set")
	}

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
		return fmt.Errorf("failed to create http GET request: %v", err)
	}
	req.Header.Add("User-Agent", utils.RandomAgent())

	if d.Headers != nil {
		for k, v := range d.Headers {
			req.Header.Add(k, v)
		}
	}

	if d.canResume {
		if f, err := os.Stat(d.DestName + ".download"); !os.IsNotExist(err) {
			// don't try to download files being downloaded elsewhere
			if d.skipAll {
				d.resume = false
				return nil
			} else if d.resumeAll {
				d.resume = true
			} else if d.restartAll {
				log.Infof("Downloading %s - RESTARTED", d.DestName+".download")
				d.resume = false
			} else {
				choice := ""
				prompt := &survey.Select{
					Message: fmt.Sprintf("Previous download of %s can be resumed:", d.DestName),
					Options: []string{"resume", "skip", "skip all", "restart"},
				}
				survey.AskOne(prompt, &choice)

				switch choice {
				case "resume":
					d.resume = true
				case "restart":
					log.Infof("Downloading %s - RESTARTED", d.DestName+".download")
					d.resume = false
				case "skip":
					log.Infof("%s - SKIPPED", d.DestName+".download")
					d.resume = false
					return nil
				case "skip all":
					log.Info("Skipping ALL active downloads (you are performing a distributed download)")
					d.skipAll = true
					d.resume = false
					return nil
				}
			}

			if d.resume {
				d.bytesResumed = f.Size()
				rangeHeader := fmt.Sprintf("bytes=%d-", d.bytesResumed)
				utils.Indent(log.WithField("range", rangeHeader).Debug, 2)("Setting Header")
				req.Header.Add("Range", rangeHeader)
			}
		}
	}

	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			if d.verbose {
				addr, _, _ := strings.Cut(connInfo.Conn.RemoteAddr().String(), ":")

				req, err := http.NewRequest("GET", fmt.Sprintf("http://ip-api.com/json/%s", addr), nil)
				if err != nil {
					log.Error("failed to create http GET request")
				}
				req.Header.Add("User-Agent", utils.RandomAgent())

				if res, err := d.client.Do(req); err == nil {
					defer res.Body.Close()
					data := &geoQuery{}
					json.NewDecoder(res.Body).Decode(data)
					utils.Indent(log.Debug, 2)(fmt.Sprintf("URL resolved to: %s (%s - %s, %s. %s)", addr, data.Org, data.City, data.Region, data.Country))
				} else {
					log.Errorf("failed to lookup IP's geolocation: %v", err)
				}
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// utils.Indent(log.WithField("file", d.DestName).Debug, 2)("Downloading") TODO: should I remove this?
	resp, err := d.client.Do(req)
	if err != nil {
		if errors.Is(err, syscall.ECONNRESET) {
			utils.Indent(log.Error, 2)(fmt.Sprintf("CONNECTION RESET: %v", err))
			utils.Indent(log.Warn, 3)("trying again...")
			return d.Do()
		}
		return fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("server return status: %s", resp.Status)
	}

	// Apple likes to return 200 OK even when the file is not found/or is not available
	if resp.Header.Get("Content-type") == "text/html; charset=UTF-8" {
		// body, err := io.ReadAll(resp.Body)
		// if err != nil {
		// 	return fmt.Errorf("failed to read response body: %v", err)
		// }
		// f, err := os.CreateTemp("", "error.html")
		// if err != nil {
		// 	return fmt.Errorf("failed to create error.html: %v", err)
		// }
		// defer f.Close()
		// log.Infof("Writing response body to %s", f.Name())
		// if _, err := f.Write(body); err != nil {
		// 	return fmt.Errorf("failed to write response body to %s: %v", f.Name(), err)
		// }
		// return fmt.Errorf("server returned a html page")
		log.Warn("Server returned a HTML page")
	}

	// fileLock := flock.New(d.DestName + ".download")
	// defer fileLock.Unlock()

	// locked, err := fileLock.TryLock()
	// if err != nil {
	// 	return errors.Wrapf(err, "unable to lock %s", d.DestName+".download")
	// }

	// if !locked {
	// 	log.Errorf("%s is being downloaded by another instance", d.DestName+".download")
	// 	return nil
	// }

	var dest *os.File
	if d.resume {
		utils.Indent(log.WithField("file", d.DestName).Warn, 2)("Resuming a previous download")
		dest, err = os.OpenFile(d.DestName+".download", os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("cannot open %s: %v", d.DestName+".download", err)
		}
		dest.Seek(0, io.SeekEnd)
	} else {
		dest, err = os.Create(d.DestName + ".download")
		if err != nil {
			return fmt.Errorf("cannot open %s: %v", d.DestName+".download", err)
		}
	}

	var p *mpb.Progress
	var reader io.ReadCloser

	if d.size > 0 {
		p = mpb.New(
			mpb.WithWidth(60),
			mpb.WithRefreshRate(180*time.Millisecond),
		)

		var bar *mpb.Bar
		bar = p.New(d.size,
			mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|"),
			mpb.PrependDecorators(
				decor.CountersKibiByte("\t% .2f / % .2f"),
			),
			mpb.AppendDecorators(
				decor.OnComplete(decor.AverageETA(decor.ET_STYLE_GO), "✅ "),
				decor.Name(" ] "),
				decor.AverageSpeed(decor.SizeB1024(0), "% .2f", decor.WCSyncWidth),
			),
		)

		if d.resume {
			bar = p.New(d.size,
				mpb.BarStyle().Lbound("[").Filler("=").Tip(">").Padding("-").Rbound("|"),
				mpb.PrependDecorators(
					decor.CountersKibiByte("\t% .2f / % .2f"),
				),
				mpb.AppendDecorators(
					decor.OnComplete(decor.AverageETA(decor.ET_STYLE_GO), "✅ "),
					decor.Name(" ] "),
					decor.AverageSpeed(decor.SizeB1024(0), "% .2f", decor.WCSyncWidth),
				),
				// mpb.AppendDecorators(
				// 	decor.OnComplete(decor.EwmaETA(decor.ET_STYLE_GO, float64(d.size)/1024), "✅ "),
				// 	decor.Name(" ] "),
				// 	decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", float64(d.size)/2048),
				// ),
			)
			bar.IncrInt64(d.bytesResumed)
			bar.SetRefill(d.bytesResumed)
			// bar.IncrInt64(d.size - d.bytesResumed)
		}

		// create proxy reader
		reader = bar.ProxyReader(resp.Body)
	} else {
		reader = resp.Body
	}
	defer reader.Close()

	if d.resume {
		if _, err := io.Copy(dest, reader); err != nil {
			return fmt.Errorf("failed to copy body reader data: %v", err)
		}

		if d.size > 0 {
			p.Wait()
		}

		// close file
		dest.Sync()
		if err := dest.Close(); err != nil {
			return fmt.Errorf("failed to close %s: %v", d.DestName+".download", err)
		}

		if len(d.Sha1) > 0 && !d.ignoreSha1 {
			utils.Indent(log.Info, 2)("verifying sha1sum...")
			if ok, _ := utils.Verify(d.Sha1, d.DestName+".download"); !ok {
				// fileLock.Unlock()
				if err := os.Remove(d.DestName + ".download"); err != nil {
					return fmt.Errorf("cannot remove downloaded file with checksum mismatch: %v", err)
				}
				return fmt.Errorf("bad download: ipsw %s sha1 hash is incorrect", d.DestName+".download")
			}
		}

	} else {
		tee := io.TeeReader(reader, dest)

		h := sha1.New()
		if _, err := io.Copy(h, tee); err != nil {
			return err
		}

		if d.size > 0 {
			p.Wait()
		}

		// close file
		dest.Sync()
		if err := dest.Close(); err != nil {
			return fmt.Errorf("failed to close %s: %v", d.DestName+".download", err)
		}

		if len(d.Sha1) > 0 && !d.ignoreSha1 {
			utils.Indent(log.Info, 2)("verifying sha1sum...")
			checksum, _ := hex.DecodeString(d.Sha1)

			if !bytes.Equal(h.Sum(nil), checksum) {
				utils.Indent(log.WithFields(log.Fields{
					"expected": d.Sha1,
					"actual":   fmt.Sprintf("%x", h.Sum(nil)),
				}).Error, 3)("❌ BAD CHECKSUM")
				// fileLock.Unlock()
				if err := os.Remove(d.DestName); err != nil {
					return fmt.Errorf("cannot remove downloaded file with checksum mismatch: %v", err)
				}
			}
		}
	}

	if err := os.Rename(d.DestName+".download", d.DestName); err != nil {
		if linkErr, ok := err.(*os.LinkError); ok {
			return fmt.Errorf("failed to rename %s to %s: link error: %v", d.DestName+".download", d.DestName, linkErr.Err)
		} else {
			return fmt.Errorf("failed to rename %s to %s: %v", d.DestName+".download", d.DestName, err)
		}
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
