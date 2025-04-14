//go:build darwin && cgo

package wallpaper

/*
#cgo CFLAGS: -x objective-c -fmodules
#cgo LDFLAGS: -framework Foundation -framework CoreGraphics -framework QuartzCore

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

#include "wallpaper.h"
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"unsafe"

	"github.com/blacktop/go-plist"
)

const (
	WallPapersFolder           = "/Library/Wallpaper/"
	DefaultWallpapersPlistGlob = "DefaultWallpapers~*.plist"
	CollectionsFolder          = "/Library/Wallpaper/Collections/"
	CollectionsPlistGlob       = "Collections~*.plist"
	CapPlayWallpapers          = "/System/Library/PrivateFrameworks/CarPlayUIServices.framework/"
	updateURL                  = "https://mesu.apple.com/assets/com_apple_MobileAsset_Wallpaper/com_apple_MobileAsset_Wallpaper.xml"
	macOsUpdateURL             = "https://mesu.apple.com/assets/macos/com_apple_MobileAsset_DesktopPicture/com_apple_MobileAsset_DesktopPicture.xml"
	macOsAerialsURL            = "https://configuration.apple.com/configurations/internetservices/aerials/resources-config-15-0.plist"
)

type WallpaperID struct {
	CollectionIdentifier string `plist:"collectionIdentifier,omitempty"`
	WallpaperIdentifier  uint64 `plist:"wallpaperIdentifier,omitempty"`
}

type DefaultWallpaper struct {
	Default WallpaperID `plist:"default,omitempty"`
}

type WallpaperCollections struct {
	Order []string `plist:"order,omitempty"`
}

type WallpaperCollectionPlist struct {
	ID              string `plist:"identifier,omitempty"`
	Name            string `plist:"name,omitempty"`
	Order           []int  `plist:"order,omitempty"`
	Source          string `plist:"source,omitempty"`
	IsLegacyContent bool   `plist:"isLegacyContent,omitempty"`
}

type WallpaperPlist struct {
	AppearanceAware         bool            `plist:"appearanceAware,omitempty"`
	Assets                  map[string]any  `plist:"assets,omitempty"`
	ContentVersion          float64         `plist:"contentVersion,omitempty"`
	Family                  string          `plist:"family,omitempty"`
	ID                      int             `plist:"identifier,omitempty"`
	LogicalScreenClass      string          `plist:"logicalScreenClass,omitempty"`
	Name                    string          `plist:"name,omitempty"`
	PreferredProminentColor ProminentColors `plist:"preferredProminentColor,omitempty"`
	Version                 int             `plist:"version,omitempty"`
}

type Assets struct {
	LockAndHome LockAndHome `plist:"lockAndHome"`
}

type LockAndHome struct {
	Default DefaultAsset `plist:"default"`
}

type DefaultAsset struct {
	BackgroundAnimationFileName  string `plist:"backgroundAnimationFileName"`
	FloatingAnimationFileNameKey string `plist:"floatingAnimationFileNameKey"`
	Identifier                   int    `plist:"identifier"`
	Name                         string `plist:"name"`
	Type                         string `plist:"type"`
}

type ProminentColors struct {
	Dark    string `plist:"dark,omitempty"`
	Default string `plist:"default,omitempty"`
}

type Wallpaper struct {
	Path string
	Meta WallpaperPlist
}

type Size struct {
	Width  int
	Height int
	Scale  int
}

func (w Wallpaper) GetSize() (*Size, error) {
	var sz Size
	re := regexp.MustCompile(`-(?P<width>\d+)w-(?P<height>\d+)h@(?P<scale>\d+)x~.*\.wallpaper$`)
	if re.MatchString(w.Path) {
		matches := re.FindStringSubmatch(w.Path)
		if len(matches) > 2 {
			var err error
			sz.Width, err = strconv.Atoi(matches[1])
			if err != nil {
				return nil, fmt.Errorf("failed to parse width: %w", err)
			}
			sz.Height, err = strconv.Atoi(matches[2])
			if err != nil {
				return nil, fmt.Errorf("failed to parse height: %w", err)
			}
			sz.Scale, err = strconv.Atoi(matches[3])
			if err != nil {
				return nil, fmt.Errorf("failed to parse scale: %w", err)
			}
		}
	} else {
		return nil, fmt.Errorf("failed to parse wallpaper size from path: %s", w.Path)
	}
	return &sz, nil
}

type Collection struct {
	Meta       WallpaperCollectionPlist
	Wallpapers []Wallpaper
}

type Wallpapers struct {
	DefaultWallpaper
	CollectionsOrder WallpaperCollections
	Collections      []Collection
	CarPlays         []string
}

func ParseFolder(mountPoint string) (*Wallpapers, error) {
	var wallpapers Wallpapers
	// parse default wallpapers plist
	defaults, err := filepath.Glob(filepath.Join(mountPoint, WallPapersFolder, DefaultWallpapersPlistGlob))
	if err != nil {
		return nil, fmt.Errorf("failed to parse folder: %w", err)
	}
	if len(defaults) == 0 {
		return nil, fmt.Errorf("no wallpapers found in %s", filepath.Join(mountPoint, WallPapersFolder))
	}
	data, err := os.ReadFile(defaults[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", defaults[0], err)
	}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&wallpapers.DefaultWallpaper); err != nil {
		return nil, fmt.Errorf("failed to decode plist %s: %w", defaults[0], err)
	}
	if wallpapers.Default.CollectionIdentifier == "" {
		return nil, fmt.Errorf("no default wallpaper collection found in %s", defaults[0])
	}
	// parse collections plist
	collections, err := filepath.Glob(filepath.Join(mountPoint, CollectionsFolder, CollectionsPlistGlob))
	if err != nil {
		return nil, fmt.Errorf("failed to parse folder: %w", err)
	}
	if len(collections) == 0 {
		return nil, fmt.Errorf("no wallpapers collections found in %s", filepath.Join(mountPoint, CollectionsFolder))
	}
	data, err = os.ReadFile(collections[0])
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", collections[0], err)
	}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&wallpapers.CollectionsOrder); err != nil {
		return nil, fmt.Errorf("failed to decode plist %s: %w", collections[0], err)
	}
	// walk through the collections folder to find all wallpapers
	// and check if the collection identifier is valid
	if err := filepath.Walk(filepath.Join(mountPoint, CollectionsFolder), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %s: %w", path, err)
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Base(path) == "WallpaperCollection.plist" {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", path, err)
			}
			var collection Collection
			if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&collection.Meta); err != nil {
				return fmt.Errorf("failed to decode plist %s: %w", path, err)
			}
			// walk through the wallpapers folder to find all wallpapers
			if err := filepath.Walk(filepath.Join(filepath.Dir(path), "Wallpapers"), func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return fmt.Errorf("error accessing path %s: %w", path, err)
				}
				if info.IsDir() {
					return nil
				}
				if filepath.Base(path) == "Wallpaper.plist" {
					data, err := os.ReadFile(path)
					if err != nil {
						return fmt.Errorf("failed to read file %s: %w", path, err)
					}
					var wp Wallpaper
					if err := plist.NewDecoder(bytes.NewReader(data)).Decode(&wp.Meta); err != nil {
						return fmt.Errorf("failed to decode plist %s: %w", path, err)
					}
					fpath, err := filepath.Rel(mountPoint, path)
					if err != nil {
						return fmt.Errorf("failed to get relative path for %s: %v", path, err)
					}
					wp.Path = filepath.Dir(fpath)
					collection.Wallpapers = append(collection.Wallpapers, wp)
				}
				return nil
			}); err != nil {
				return err
			}

			wallpapers.Collections = append(wallpapers.Collections, collection)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk through collections folder: %w", err)
	}
	// walk through the CarPlay wallpapers folder to find all wallpapers
	if err := filepath.Walk(filepath.Join(mountPoint, CapPlayWallpapers), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %s: %w", path, err)
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".heic" {
			fpath, err := filepath.Rel(mountPoint, path)
			if err != nil {
				return fmt.Errorf("failed to get relative path for %s: %v", path, err)
			}
			wallpapers.CarPlays = append(wallpapers.CarPlays, fpath)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("failed to walk through CarPlay wallpapers folder: %w", err)
	}

	return &wallpapers, nil
}

// ParseCAMLWallpaper parses a CAML file and returns wallpaper data
func ParseCAMLWallpaper(camlPath string) ([]byte, error) {
	cPath := C.CString(camlPath)
	defer C.free(unsafe.Pointer(cPath))

	var outSize C.size_t
	var cError C.wallpaper_error_t
	result := C.parse_caml_wallpaper(cPath, &outSize, &cError)

	// Handle error if one occurred
	if cError.message != nil {
		errMsg := C.GoString(cError.message)
		C.free(unsafe.Pointer(cError.message))
		return nil, fmt.Errorf("CAML parse error (code %d): %s", cError.code, errMsg)
	}

	if result == nil {
		return nil, errors.New("failed to parse CAML wallpaper")
	}

	// Convert C buffer to Go slice
	data := C.GoBytes(unsafe.Pointer(result), C.int(outSize))
	// Free the C buffer
	C.free(unsafe.Pointer(result))

	return data, nil
}

// ExtractWallpaperImages extracts wallpaper images from a CAML package
func ExtractWallpaperImages(camlPath, outputDir string) ([]string, error) {
	absPath, err := filepath.Abs(camlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	cPath := C.CString(absPath)
	defer C.free(unsafe.Pointer(cPath))

	cOutDir := C.CString(outputDir)
	defer C.free(unsafe.Pointer(cOutDir))

	var numImages C.int
	var cError C.wallpaper_error_t
	imagePathsPtr := C.extract_caml_images(cPath, cOutDir, &numImages, &cError)

	// Handle error if one occurred
	if cError.message != nil {
		errMsg := C.GoString(cError.message)
		C.free(unsafe.Pointer(cError.message))
		return nil, fmt.Errorf("CAML extract error (code %d): %s", cError.code, errMsg)
	}

	if imagePathsPtr == nil {
		return nil, errors.New("failed to extract wallpaper images")
	}

	// Convert C string array to Go slice
	imagePaths := make([]string, int(numImages))
	imagePathsArr := (*[1 << 30]*C.char)(unsafe.Pointer(imagePathsPtr))

	for i := range int(numImages) {
		imagePaths[i] = C.GoString(imagePathsArr[i])
		C.free(unsafe.Pointer(imagePathsArr[i]))
	}

	C.free(unsafe.Pointer(imagePathsPtr))

	return imagePaths, nil
}
