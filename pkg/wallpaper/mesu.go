//go:build darwin && wallpaper

package wallpaper

import (
	"bytes"
	"fmt"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/disintegration/imaging"
)

const (
	updateURL       = "https://mesu.apple.com/assets/com_apple_MobileAsset_Wallpaper/com_apple_MobileAsset_Wallpaper.xml"
	macOsUpdateURL  = "https://mesu.apple.com/assets/macos/com_apple_MobileAsset_DesktopPicture/com_apple_MobileAsset_DesktopPicture.xml"
	macOsAerialsURL = "https://configuration.apple.com/configurations/internetservices/aerials/resources-config-15-0.plist"
)

type WallpaperAsset struct {
	Build                       string `plist:"Build,omitempty"`
	WallpaperBundleName         string `plist:"WallpaperBundleName,omitempty"`
	WallpaperIdentifier         int    `plist:"WallpaperIdentifier,omitempty"`
	WallpaperLogicalScreenClass string `plist:"WallpaperLogicalScreenClass,omitempty"`
	WallpaperName               string `plist:"WallpaperName,omitempty"`
	CompatibilityVersion        int    `plist:"_CompatibilityVersion,omitempty"`
	CompressionAlgorithm        string `plist:"_CompressionAlgorithm,omitempty"`
	ContentVersion              int    `plist:"_ContentVersion,omitempty"`
	DownloadSize                int64  `plist:"_DownloadSize,omitempty"`
	IsZipStreamable             bool   `plist:"_IsZipStreamable,omitempty"`
	MasteredVersion             string `plist:"_MasteredVersion,omitempty"`
	Measurement                 []byte `plist:"_Measurement,omitempty"`
	MeasurementAlgorithm        string `plist:"_MeasurementAlgorithm,omitempty"`
	UnarchivedSize              int64  `plist:"_UnarchivedSize,omitempty"`
	BaseURL                     string `plist:"__BaseURL,omitempty"`
	CanUseLocalCacheServer      bool   `plist:"__CanUseLocalCacheServer,omitempty"`
	RelativePath                string `plist:"__RelativePath,omitempty"`
	RequiredByOS                bool   `plist:"__RequiredByOS,omitempty"`
}

type MESUAssets struct {
	AssetType     string           `plist:"AssetType,omitempty"`
	Assets        []WallpaperAsset `plist:"Assets,omitempty"`
	Certificate   []byte           `plist:"Certificate,omitempty"`
	FormatVersion int              `plist:"FormatVersion,omitempty"`
	Signature     []byte           `plist:"Signature,omitempty"`
	SigningKey    string           `plist:"SigningKey,omitempty"`
}

func resizeJPEGThumbnail(imgBytes []byte) ([]byte, error) {
	img, err := jpeg.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return nil, fmt.Errorf("unable to decode thumbnail.jpg: %v", err)
	}

	resizedImg := imaging.Resize(img, 0, 700, imaging.Lanczos)
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, resizedImg, &jpeg.Options{Quality: 90}); err != nil {
		return nil, fmt.Errorf("unable to encode resized thumbnail: %v", err)
	}

	return buf.Bytes(), nil
}

func resizePNGThumbnail(imgBytes []byte) ([]byte, error) {
	img, err := png.Decode(bytes.NewReader(imgBytes))
	if err != nil {
		return nil, fmt.Errorf("unable to decode thumbnail.png: %v", err)
	}

	resizedImg := imaging.Resize(img, 0, 700, imaging.Lanczos)
	var buf bytes.Buffer
	if err := png.Encode(&buf, resizedImg); err != nil {
		return nil, fmt.Errorf("unable to encode resized thumbnail: %v", err)
	}

	return buf.Bytes(), nil
}

// convertWithSips uses macOS ImageIO via sips for HEIC-family wallpaper previews.
func convertWithSips(imgBytes []byte, sourceExt string) ([]byte, error) {
	tempDir, err := os.MkdirTemp("", "ipsw-wallpaper-*")
	if err != nil {
		return nil, fmt.Errorf("unable to create temporary directory for %s preview: %w", sourceExt, err)
	}
	defer os.RemoveAll(tempDir)

	sourcePath := filepath.Join(tempDir, "thumbnail"+sourceExt)
	if err := os.WriteFile(sourcePath, imgBytes, 0o600); err != nil {
		return nil, fmt.Errorf("unable to write temporary %s preview: %w", sourceExt, err)
	}

	outputPath := filepath.Join(tempDir, "thumbnail.png")
	cmd := exec.Command("sips", "--resampleHeight", "700", "-s", "format", "png", sourcePath, "--out", outputPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("sips failed to convert %s preview: %w (%s)", sourceExt, err, strings.TrimSpace(string(output)))
	}

	converted, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read converted %s preview: %w", sourceExt, err)
	}

	return converted, nil
}

func extractThumbnailPreview(imgBytes []byte, thumbnailFile string) ([]byte, error) {
	thumbnailExt := strings.ToLower(filepath.Ext(thumbnailFile))
	if bytes.HasPrefix(imgBytes, []byte("\x89PNG")) {
		thumbnailExt = ".png"
	}

	switch thumbnailExt {
	case ".avif", ".heic", ".heif":
		converted, err := convertWithSips(imgBytes, thumbnailExt)
		if err != nil {
			return nil, fmt.Errorf("unable to decode %s preview: %w", thumbnailExt, err)
		}
		return converted, nil
	case ".jpeg", ".jpg":
		return resizeJPEGThumbnail(imgBytes)
	case ".png":
		return resizePNGThumbnail(imgBytes)
	default:
		return nil, fmt.Errorf("unsupported thumbnail format: %s", thumbnailExt)
	}
}

// FetchWallpaperPlist fetches and decodes the Apple wallpaper plist
func FetchWallpaperPlist() (*MESUAssets, error) {
	resp, err := http.Get(updateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch wallpaper plist: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read wallpaper plist: %w", err)
	}
	var assets MESUAssets
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&assets); err != nil {
		return nil, fmt.Errorf("failed to decode wallpaper plist: %w", err)
	}
	return &assets, nil
}

// ExtractThumbnailBytes downloads a wallpaper zip from the given URL and extracts the thumbnail image to a byte slice,
// resizing it to a fixed height while preserving aspect ratio.
func ExtractThumbnailBytes(url, proxy string, insecure bool) ([]byte, error) {
	zr, err := download.NewRemoteZipReader(url, &download.RemoteConfig{
		Proxy:    proxy,
		Insecure: insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to download remote zip: %v", err)
	}
	var thumbnailFile string
	for _, f := range zr.File {
		if filepath.Base(f.Name) == "Wallpaper.plist" {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("unable to open Wallpaper.plist: %v", err)
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("unable to read Wallpaper.plist: %v", err)
			}

			var wp Wallpaper
			if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&wp.Meta); err != nil {
				return nil, fmt.Errorf("failed to decode plist %s: %w", f.Name, err)
			}

			if lH, ok := wp.Meta.Assets["lockAndHome"].(map[string]any); ok {
				if dlt, ok := lH["default"].(map[string]any); ok {
					if thumbnailFile, ok = dlt["thumbnailImageFileName"].(string); !ok {
						if fullSized, ok := dlt["fullSizeImageFileName"].(string); ok {
							thumbnailFile = fullSized
						} else {
							return nil, fmt.Errorf("unable to find thumbnailImageFileName or fullSizeImageFileName in Wallpaper.plist")
						}
					}
				}
			}
		}
	}
	for _, f := range zr.File {
		if filepath.Base(f.Name) == thumbnailFile {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("unable to open thumbnail image %s: %v", thumbnailFile, err)
			}
			defer rc.Close()
			imgBytes, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("unable to read thumbnail image %s: %v", thumbnailFile, err)
			}
			return extractThumbnailPreview(imgBytes, thumbnailFile)
		}
	}

	return nil, fmt.Errorf("unable to find thumbnail image in wallpaper zip")
}
