package wallpaper

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/blacktop/go-plist"
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
