//go:build darwin && cgo && wallpaper

package wallpaper

import (
	"bytes"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"path/filepath"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/disintegration/imaging"
	_ "github.com/strukturag/libheif-go"
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

// ExtractThumbnailBytes downloads a wallpaper zip from the given URL and extracts the thumbnail.jpg to a byte slice,
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
				return nil, fmt.Errorf("unable to open thumbnail.jpg: %v", err)
			}
			defer rc.Close()
			imgBytes, err := io.ReadAll(rc)
			if err != nil {
				return nil, fmt.Errorf("unable to read thumbnail.jpg: %v", err)
			}
			if bytes.HasPrefix(imgBytes, []byte("\x89PNG")) {
				thumbnailFile = "thumbnail.png"
			}
			switch filepath.Ext(thumbnailFile) {
			case ".heic":
				img, format, err := image.Decode(bytes.NewReader(imgBytes))
				if err != nil {
					return nil, fmt.Errorf("unable to decode thumbnail.heic: %v", err)
				}
				if format != "heif" && format != "heic" && format != "avif" {
					return nil, fmt.Errorf("unsupported thumbnail format: %s", format)
				}
				resizedImg := imaging.Resize(img, 0, 700, imaging.Lanczos)
				var buf bytes.Buffer
				if err := png.Encode(&buf, resizedImg); err != nil {
					return nil, fmt.Errorf("could not encode image as PNG: %w", err)
				}
				return buf.Bytes(), nil
			case ".jpeg", ".jpg":
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
			case ".png":
				img, err := png.Decode(bytes.NewReader(imgBytes))
				if err != nil {
					return nil, fmt.Errorf("unable to decode thumbnail.jpg: %v", err)
				}
				resizedImg := imaging.Resize(img, 0, 700, imaging.Lanczos)
				var buf bytes.Buffer
				if err := png.Encode(&buf, resizedImg); err != nil {
					return nil, fmt.Errorf("unable to encode resized thumbnail: %v", err)
				}
				return buf.Bytes(), nil
			default:
				return nil, fmt.Errorf("unsupported thumbnail format: %s", filepath.Ext(thumbnailFile))
			}
		}
	}

	return nil, fmt.Errorf("unable to find thumbnail.jpg in wallpaper zip")
}
