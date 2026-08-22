package download

import (
	"context"
	"fmt"
	"os"
	"strings"

	internaldownload "github.com/blacktop/ipsw/internal/download"
)

const sha1ChecksumsFile = "checksums.txt.sha1"

func runIPSWDownload(ctx context.Context, downloader *internaldownload.Download, sum, destName string, recordChecksum bool) (bool, error) {
	status, err := downloader.DoContext(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to download file: %w", err)
	}
	if status != internaldownload.Downloaded {
		// locked by another download process (--skip-all): the lock owner
		// installs the file; do not record or report it as ours
		return false, nil
	}
	if recordChecksum {
		if err := appendSHA1Checksum(sum, destName); err != nil {
			return false, err
		}
	}
	return true, nil
}

func appendSHA1Checksum(sum, destName string) error {
	sum = strings.ToLower(strings.TrimSpace(sum))
	if !internaldownload.ValidSHA1(sum) {
		return nil
	}
	f, err := os.OpenFile(sha1ChecksumsFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", sha1ChecksumsFile, err)
	}
	if _, err := fmt.Fprintf(f, "%s  %s\n", sum, destName); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write to %s: %w", sha1ChecksumsFile, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", sha1ChecksumsFile, err)
	}
	return nil
}
