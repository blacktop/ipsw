/*
Copyright © 2018-2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package ent

import (
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/pkg/info"
)

// DetectPlatformFromIPSW detects the platform from IPSW filename and metadata
func DetectPlatformFromIPSW(ipswPath string, ipswInfo *info.Info) model.Platform {
	filename := strings.ToLower(filepath.Base(ipswPath))

	// First, try to detect from filename patterns
	if platform := detectPlatformFromFilename(filename); platform != "" {
		return platform
	}

	// If filename detection fails, try from device types in BuildManifest
	if ipswInfo != nil && ipswInfo.Plists.BuildManifest != nil {
		if platform := detectPlatformFromDevices(ipswInfo.Plists.BuildManifest.SupportedProductTypes); platform != "" {
			return platform
		}
	}

	// Default fallback to iOS
	return model.PlatformIOS
}

// detectPlatformFromFilename detects platform from IPSW filename patterns
func detectPlatformFromFilename(filename string) model.Platform {
	// macOS patterns (most specific first)
	macOSPatterns := []string{
		"universalmac", "macos", "mac_os", "macbook", "imac", "macmini", "macpro", "macstudio",
	}

	// visionOS patterns (check before general patterns to avoid conflicts)
	visionOSPatterns := []string{
		"apple_vision_pro", "vision_pro", "visionos", "vision_os", "applevision", "realityos", "realitydevice",
	}

	// watchOS patterns
	watchOSPatterns := []string{
		"watchos", "watch_os", "watch7", "watch6", "watch5", "applewatch",
	}

	// tvOS patterns
	tvOSPatterns := []string{
		"tvos", "tv_os", "appletv", "apple_tv",
	}

	// Check each platform pattern (order matters - most specific first)
	for _, pattern := range visionOSPatterns {
		if strings.Contains(filename, pattern) {
			return model.PlatformVisionOS
		}
	}

	for _, pattern := range macOSPatterns {
		if strings.Contains(filename, pattern) {
			return model.PlatformMacOS
		}
	}

	for _, pattern := range watchOSPatterns {
		if strings.Contains(filename, pattern) {
			return model.PlatformWatchOS
		}
	}

	for _, pattern := range tvOSPatterns {
		if strings.Contains(filename, pattern) {
			return model.PlatformTvOS
		}
	}

	// If no patterns match, return empty (caller will try other methods)
	return ""
}

// detectPlatformFromDevices detects platform from device identifiers
func detectPlatformFromDevices(devices []string) model.Platform {
	if len(devices) == 0 {
		return ""
	}

	// Count device types to determine platform
	iosCount := 0
	macOSCount := 0
	watchOSCount := 0
	tvOSCount := 0
	visionOSCount := 0

	for _, device := range devices {
		deviceLower := strings.ToLower(device)

		// macOS device patterns
		if strings.Contains(deviceLower, "mac") ||
			strings.Contains(deviceLower, "vmware") ||
			strings.Contains(deviceLower, "parallels") {
			macOSCount++
		} else if strings.Contains(deviceLower, "watch") {
			watchOSCount++
		} else if strings.Contains(deviceLower, "appletv") ||
			strings.Contains(deviceLower, "atv") {
			tvOSCount++
		} else if strings.Contains(deviceLower, "realitydevice") ||
			strings.Contains(deviceLower, "vision") {
			visionOSCount++
		} else if strings.Contains(deviceLower, "iphone") ||
			strings.Contains(deviceLower, "ipad") ||
			strings.Contains(deviceLower, "ipod") ||
			strings.Contains(deviceLower, "simulator") {
			iosCount++
		}
	}

	// Return platform with highest count
	maxCount := iosCount
	platform := model.PlatformIOS

	if macOSCount > maxCount {
		maxCount = macOSCount
		platform = model.PlatformMacOS
	}
	if watchOSCount > maxCount {
		maxCount = watchOSCount
		platform = model.PlatformWatchOS
	}
	if tvOSCount > maxCount {
		maxCount = tvOSCount
		platform = model.PlatformTvOS
	}
	if visionOSCount > maxCount {
		platform = model.PlatformVisionOS
	}

	return platform
}

// GetAllPlatforms returns all supported platforms
func GetAllPlatforms() []model.Platform {
	return []model.Platform{
		model.PlatformIOS,
		model.PlatformMacOS,
		model.PlatformWatchOS,
		model.PlatformTvOS,
		model.PlatformVisionOS,
	}
}

// FormatPlatformForDisplay formats platform name for user display
func FormatPlatformForDisplay(platform model.Platform) string {
	switch platform {
	case model.PlatformIOS:
		return "iOS"
	case model.PlatformMacOS:
		return "macOS"
	case model.PlatformWatchOS:
		return "watchOS"
	case model.PlatformTvOS:
		return "tvOS"
	case model.PlatformVisionOS:
		return "visionOS"
	default:
		return string(platform)
	}
}
