package plist

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/blacktop/go-plist"
)

// AppInfo is the Info.plist object found in .app files
// https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html#//apple_ref/doc/uid/TP40009248-SW1
type AppInfo struct {
	BuildMachineOSBuild           string   `plist:"BuildMachineOSBuild,omitempty"`
	CFBundleDevelopmentRegion     string   `plist:"CFBundleDevelopmentRegion,omitempty"`
	CFBundleDocumentTypes         []any    `plist:"CFBundleDocumentTypes,omitempty"`
	CFBundleExecutable            string   `plist:"CFBundleExecutable,omitempty"`
	CFBundleIconFile              string   `plist:"CFBundleIconFile,omitempty"`
	CFBundleIconName              string   `plist:"CFBundleIconName,omitempty"`
	CFBundleIdentifier            string   `plist:"CFBundleIdentifier,omitempty"`
	CFBundleInfoDictionaryVersion string   `plist:"CFBundleInfoDictionaryVersion,omitempty"`
	CFBundleName                  string   `plist:"CFBundleName,omitempty"`
	CFBundlePackageType           string   `plist:"CFBundlePackageType,omitempty"`
	CFBundleShortVersionString    string   `plist:"CFBundleShortVersionString,omitempty"`
	CFBundleSignature             string   `plist:"CFBundleSignature,omitempty"`
	CFBundleSupportedPlatforms    []string `plist:"CFBundleSupportedPlatforms,omitempty"`
	CFBundleURLTypes              []struct {
		CFBundleTypeRole    string   `plist:"CFBundleTypeRole,omitempty"`
		CFBundleURLIconFile string   `plist:"CFBundleURLIconFile,omitempty"`
		CFBundleURLName     string   `plist:"CFBundleURLName,omitempty"`
		CFBundleURLSchemes  []string `plist:"CFBundleURLSchemes,omitempty"`
	} `plist:"CFBundleURLTypes,omitempty"`
	CFBundleVersion                      string   `plist:"CFBundleVersion,omitempty"`
	DTCompiler                           string   `plist:"DTCompiler,omitempty"`
	DTPlatformBuild                      string   `plist:"DTPlatformBuild,omitempty"`
	DTPlatformName                       string   `plist:"DTPlatformName,omitempty"`
	DTPlatformVersion                    string   `plist:"DTPlatformVersion,omitempty"`
	DTSDKBuild                           string   `plist:"DTSDKBuild,omitempty"`
	DTSDKName                            string   `plist:"DTSDKName,omitempty"`
	DTXcode                              string   `plist:"DTXcode,omitempty"`
	DTXcodeBuild                         string   `plist:"DTXcodeBuild,omitempty"`
	LSApplicationCategoryType            string   `plist:"LSApplicationCategoryType,omitempty"`
	LSMinimumSystemVersion               string   `plist:"LSMinimumSystemVersion,omitempty"`
	LSUIElement                          bool     `plist:"LSUIElement,omitempty"`
	MinimumOSVersion                     string   `plist:"MinimumOSVersion,omitempty"`
	NSHumanReadableCopyright             string   `plist:"NSHumanReadableCopyright,omitempty"`
	NSMainNibFile                        string   `plist:"NSMainNibFile,omitempty"`
	NSPrincipalClass                     string   `plist:"NSPrincipalClass,omitempty"`
	NSSupportsAutomaticGraphicsSwitching bool     `plist:"NSSupportsAutomaticGraphicsSwitching,omitempty"`
	NSUbiquitousDisplaySet               string   `plist:"NSUbiquitousDisplaySet,omitempty"`
	NSUserActivityTypes                  []string `plist:"NSUserActivityTypes,omitempty"`
	NSUserNotificationAlertStyle         string   `plist:"NSUserNotificationAlertStyle,omitempty"`
	NSUserNotificationAlertBody          string   `plist:"NSUserNotificationAlertBody,omitempty"`
	UTExportedTypeDeclarations           []any    `plist:"UTExportedTypeDeclarations,omitempty"`
}

func (r *AppInfo) String() string {
	var out string
	out += "[Info]\n"
	out += "======\n"
	out += fmt.Sprintf("CFBundleDevelopmentRegion: %s\n", r.CFBundleDevelopmentRegion)
	out += fmt.Sprintf("CFBundleExecutable: %s\n", r.CFBundleExecutable)
	out += fmt.Sprintf("CFBundleIdentifier: %s\n", r.CFBundleIdentifier)
	out += fmt.Sprintf("CFBundleInfoDictionaryVersion: %s\n", r.CFBundleInfoDictionaryVersion)
	out += fmt.Sprintf("CFBundleName: %s\n", r.CFBundleName)
	out += fmt.Sprintf("CFBundlePackageType: %s\n", r.CFBundlePackageType)
	out += fmt.Sprintf("CFBundleShortVersionString: %s\n", r.CFBundleShortVersionString)
	out += fmt.Sprintf("CFBundleSignature: %s\n", r.CFBundleSignature)
	out += fmt.Sprintf("CFBundleSupportedPlatforms: %s\n", r.CFBundleSupportedPlatforms)
	out += fmt.Sprintf("CFBundleURLTypes: %s\n", r.CFBundleURLTypes)
	out += fmt.Sprintf("CFBundleVersion: %s\n", r.CFBundleVersion)
	return out
}

// ParseAppInfo parses the .app/Info.plist
func ParseAppInfo(data []byte) (*AppInfo, error) {
	i := &AppInfo{}
	if err := plist.NewDecoder(bytes.NewReader(data)).Decode(i); err != nil {
		return nil, fmt.Errorf("failed to parse Info.plist: %w", err)
	}
	return i, nil
}

// GetBinaryInApp returns the binary path of the given .app
func GetBinaryInApp(path string) (string, error) {
	if filepath.Ext(path) == ".app" {
		infoPath := filepath.Join(path, "Info.plist")
		if _, err := os.Stat(filepath.Join(path, "Info.plist")); err == nil { // iOS
			dat, err := ioutil.ReadFile(infoPath)
			if err != nil {
				return "", fmt.Errorf("failed to read %s: %w", infoPath, err)
			}
			ainfo, err := ParseAppInfo(dat)
			if err != nil {
				return "", fmt.Errorf("failed to parse %s: %w", infoPath, err)
			}
			if ainfo.CFBundleExecutable != "" {
				return filepath.Join(path, ainfo.CFBundleExecutable), nil
			}
			return "", fmt.Errorf("failed to find CFBundleExecutable in %s", infoPath)
		} else if _, err := os.Stat(filepath.Join(path, "Contents", "Info.plist")); err == nil { // MacOS
			infoPath = filepath.Join(path, "Contents", "Info.plist")
			dat, err := ioutil.ReadFile(infoPath)
			if err != nil {
				return "", fmt.Errorf("failed to read %s: %w", infoPath, err)
			}
			ainfo, err := ParseAppInfo(dat)
			if err != nil {
				return "", fmt.Errorf("failed to parse %s: %w", infoPath, err)
			}
			if ainfo.CFBundleExecutable != "" {
				return filepath.Join(path, "Contents", "MacOS", ainfo.CFBundleExecutable), nil
			}
			return "", fmt.Errorf("failed to find CFBundleExecutable in %s", infoPath)
		}
	}
	return "", fmt.Errorf("%s is not a .app/<binary> or a .app/Contents/MacOS/<binary>", path)
}
