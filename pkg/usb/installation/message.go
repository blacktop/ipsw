package installation

type ClientOptions struct {
	ReturnAttributes []string `plist:"ReturnAttributes,omitempty"`
}

type Command struct {
	Command       string         `plist:"Command"`
	ClientOptions *ClientOptions `plist:"ClientOptions,omitempty"`
}

func NewCommand(cmd string, returnAttributes ...string) Command {
	rb := Command{
		Command: cmd,
	}
	if len(returnAttributes) > 0 {
		rb.ClientOptions = &ClientOptions{
			ReturnAttributes: returnAttributes,
		}
	}
	return rb
}

type Lookup struct {
	Command
	ApplicationIdentifier string `plist:"ApplicationIdentifier"`
}

type LookupResult struct {
	LookupResult map[string]*AppBundle `plist:"LookupResult"`
}

type Browse struct {
	Command
}

type InstallOrUpgradeRequest struct {
	Command
	PackagePath string `plist:"PackagePath"`
}

type ApplicationIdentifierRequest struct {
	Command
	ApplicationIdentifier string `plist:"ApplicationIdentifier"`
}

type ProgressEvent struct {
	Status          string `plist:"Status"`
	PercentComplete int    `plist:"PercentComplete"`
}

type LookupArchivesRequest struct {
	Command
}

type AppBundle struct {
	ApplicationType     string `plist:"ApplicationType"`
	BuildMachineOSBuild string `plist:"BuildMachineOSBuild"`
	CFBundleDisplayName string `plist:"CFBundleDisplayName"`
	CFBundleExecutable  string `plist:"CFBundleExecutable"`
	CFBundleIcons       struct {
		CFBundleAlternateIcons map[string]*struct {
			CFBundleIconFiles []string    `plist:"CFBundleIconFiles"`
			UIPrerenderedIcon interface{} `plist:"UIPrerenderedIcon"`
		}
	} `plist:"CFBundleIcons"`
	CFBundleIdentifier            string   `plist:"CFBundleIdentifier"`
	CFBundleInfoDictionaryVersion string   `plist:"CFBundleInfoDictionaryVersion"`
	CFBundleName                  string   `plist:"CFBundleName"`
	CFBundleNumericVersion        int      `plist:"CFBundleNumericVersion"`
	CFBundlePackageType           string   `plist:"CFBundlePackageType"`
	CFBundleShortVersionString    string   `plist:"CFBundleShortVersionString"`
	CFBundleSupportedPlatforms    []string `plist:"CFBundleSupportedPlatforms"`
	CFBundleURLTypes              []*struct {
		CFBundleURLSchemes []string `plist:"CFBundleURLSchemes"`
		CFBundleTypeRole   string   `plist:"CFBundleTypeRole,omitempty"`
	} `plist:"CFBundleURLTypes"`
	CFBundleVersion                          string                 `plist:"CFBundleVersion"`
	Container                                string                 `plist:"Container"`
	DTAppStoreToolsBuild                     string                 `plist:"DTAppStoreToolsBuild"`
	DTCompiler                               string                 `plist:"DTCompiler"`
	DTPlatformBuild                          string                 `plist:"DTPlatformBuild"`
	DTPlatformName                           string                 `plist:"DTPlatformName"`
	DTPlatformVersion                        string                 `plist:"DTPlatformVersion"`
	DTSDKBuild                               string                 `plist:"DTSDKBuild"`
	DTSDKName                                string                 `plist:"DTSDKName"`
	DTXcode                                  string                 `plist:"DTXcode"`
	DTXcodeBuild                             string                 `plist:"DTXcodeBuild"`
	Entitlements                             map[string]interface{} `plist:"Entitlements"`
	EnvironmentVariables                     map[string]string      `plist:"EnvironmentVariables"`
	GroupContainers                          map[string]string      `plist:"GroupContainers"`
	ITSAppUsesNonExemptEncryption            bool                   `plist:"ITSAppUsesNonExemptEncryption"`
	IsDemotedApp                             bool                   `plist:"IsDemotedApp"`
	IsUpgradeable                            bool                   `plist:"IsUpgradeable"`
	LSApplicationQueriesSchemes              interface{}            `plist:"LSApplicationQueriesSchemes"`
	LSRequiresIPhoneOS                       bool                   `plist:"LSRequiresIPhoneOS"`
	MinimumOSVersion                         string                 `plist:"MinimumOSVersion"`
	NSUserActivityTypes                      []string               `plist:"NSUserActivityTypes"`
	ParallelPlaceholderPath                  bool                   `plist:"ParallelPlaceholderPath"`
	Path                                     string                 `plist:"Path"`
	ProfileValidated                         bool                   `plist:"ProfileValidated"`
	SequenceNumber                           int                    `plist:"SequenceNumber"`
	SignerIdentity                           string                 `plist:"SignerIdentity"`
	UIAppFonts                               []string               `plist:"UIAppFonts"`
	UIBackgroundModes                        []string               `plist:"UIBackgroundModes"`
	UIDeviceFamily                           []int                  `plist:"UIDeviceFamily"`
	UILaunchStoryboardName                   string                 `plist:"UILaunchStoryboardName"`
	UIRequiredDeviceCapabilities             []string               `plist:"UIRequiredDeviceCapabilities"`
	UIStatusBarHidden                        bool                   `plist:"UIStatusBarHidden"`
	UIStatusBarStyle                         string                 `plist:"UIStatusBarStyle"`
	UISupportedDevices                       []string               `plist:"UISupportedDevices"`
	UISupportedInterfaceOrientations         []string               `plist:"UISupportedInterfaceOrientations"`
	UIViewControllerBasedStatusBarAppearance bool                   `plist:"UIViewControllerBasedStatusBarAppearance"`
}
