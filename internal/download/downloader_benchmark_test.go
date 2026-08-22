package download

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const benchmarkMiB = int64(1 << 20)

type benchmarkRateWriter struct {
	http.ResponseWriter
	bytesPerSecond int64
}

func (w *benchmarkRateWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		time.Sleep(time.Duration(n) * time.Second / time.Duration(w.bytesPerSecond))
	}
	return n, err
}

// BenchmarkDownload exercises Download.Do end to end, including integrity
// verification. The constrained profiles limit each response independently so
// multipart range requests can demonstrate their aggregate throughput.
func BenchmarkDownload(b *testing.B) {
	dir := b.TempDir()
	profiles := []struct {
		name           string
		size           int64
		latency        time.Duration
		bytesPerSecond int64
	}{
		{name: "unlimited-1m", size: benchmarkMiB},
		{name: "unlimited-8m", size: 8 * benchmarkMiB},
		{name: "unlimited-64m", size: 64 * benchmarkMiB},
		{name: "latency-1m", size: benchmarkMiB, latency: 25 * time.Millisecond},
		{name: "latency-8m", size: 8 * benchmarkMiB, latency: 25 * time.Millisecond},
		{name: "constrained-8m", size: 8 * benchmarkMiB, latency: 25 * time.Millisecond, bytesPerSecond: 16 * benchmarkMiB},
		{name: "constrained-64m", size: 64 * benchmarkMiB, latency: 25 * time.Millisecond, bytesPerSecond: 16 * benchmarkMiB},
		{name: "constrained-128m", size: 128 * benchmarkMiB, latency: 25 * time.Millisecond, bytesPerSecond: 16 * benchmarkMiB},
	}
	for _, profile := range profiles {
		b.Run(profile.name, func(b *testing.B) {
			sourcePath := filepath.Join(dir, "source-"+profile.name+".bin")
			source, err := os.Create(sourcePath)
			if err != nil {
				b.Fatal(err)
			}
			if err := source.Truncate(profile.size); err != nil {
				b.Fatal(err)
			}
			if err := source.Close(); err != nil {
				b.Fatal(err)
			}

			source, err = os.Open(sourcePath)
			if err != nil {
				b.Fatal(err)
			}
			h := sha1.New()
			if _, err := io.Copy(h, source); err != nil {
				b.Fatal(err)
			}
			if err := source.Close(); err != nil {
				b.Fatal(err)
			}
			checksum := fmt.Sprintf("%x", h.Sum(nil))

			var activeRequests atomic.Int64
			var maxRequests atomic.Int64
			var rangeRequests atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead {
					active := activeRequests.Add(1)
					defer activeRequests.Add(-1)
					for current := maxRequests.Load(); active > current; current = maxRequests.Load() {
						if maxRequests.CompareAndSwap(current, active) {
							break
						}
					}
					if r.Header.Get("Range") != "" {
						rangeRequests.Add(1)
					}
				}
				if profile.latency > 0 {
					time.Sleep(profile.latency)
				}
				f, err := os.Open(sourcePath)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				defer f.Close()
				var out http.ResponseWriter = w
				if profile.bytesPerSecond > 0 && r.Method != http.MethodHead {
					out = &benchmarkRateWriter{ResponseWriter: w, bytesPerSecond: profile.bytesPerSecond}
				}
				http.ServeContent(out, r, "payload.bin", time.Unix(1, 0), f)
			}))
			b.Cleanup(server.Close)

			d := NewDownload("", false, false, false, false)
			d.URL = server.URL + "/payload.bin"
			d.Sha1 = checksum
			d.Headers = map[string]string{"User-Agent": "ipsw-download-benchmark"}

			b.SetBytes(profile.size)
			b.ReportAllocs()
			iteration := 0
			for b.Loop() {
				d.DestName = filepath.Join(dir, fmt.Sprintf("%s-%d.bin", profile.name, iteration))
				iteration++
				if _, err := d.Do(); err != nil {
					b.Fatal(err)
				}

				b.StopTimer()
				info, err := os.Stat(d.DestName)
				if err != nil {
					b.Fatal(err)
				}
				if info.Size() != profile.size {
					b.Fatalf("download size = %d, want %d", info.Size(), profile.size)
				}
				if err := os.Remove(d.DestName); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			b.ReportMetric(float64(maxRequests.Load()), "max-requests")
			b.ReportMetric(float64(rangeRequests.Load())/float64(iteration), "range-requests/op")
		})
	}
}
