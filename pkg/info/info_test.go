package info

import (
	"slices"
	"testing"

	"github.com/blacktop/ipsw/pkg/plist"
)

func TestKernelCacheBuildManifestFallbackForSingleDeviceIPSW(t *testing.T) {
	inf := &Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				SupportedProductTypes: []string{"iPhone8,2"},
				BuildIdentities: []plist.BuildIdentity{
					testBuildIdentity("", "n66ap", "kernelcache.release.n66"),
					testBuildIdentity("", "n66ap", "kernelcache.release.n66"),
					testBuildIdentity("", "n66map", "kernelcache.release.n66m"),
				},
			},
		},
	}

	kernels := inf.GetKernelCacheForDevice("iPhone8,2")
	wantKernels := []string{"kernelcache.release.n66", "kernelcache.release.n66m"}
	if !slices.Equal(kernels, wantKernels) {
		t.Fatalf("GetKernelCacheForDevice() = %#v, want %#v", kernels, wantKernels)
	}

	devices := inf.GetDevicesForKernelCache("kernelcache.release.n66")
	wantDevices := []string{"iPhone8,2"}
	if !slices.Equal(devices, wantDevices) {
		t.Fatalf("GetDevicesForKernelCache() = %#v, want %#v", devices, wantDevices)
	}

	if got := inf.GetKernelCacheFileName("kernelcache.release.n66"); got != "kernelcache.release.n66" {
		t.Fatalf("GetKernelCacheFileName() = %q, want original kernelcache name", got)
	}
}

func TestKernelCacheBuildManifestFallbackUsesProductType(t *testing.T) {
	inf := &Info{
		Plists: &plist.Plists{
			BuildManifest: &plist.BuildManifest{
				SupportedProductTypes: []string{"iPhone1,1", "iPhone1,2"},
				BuildIdentities: []plist.BuildIdentity{
					testBuildIdentity("iPhone1,1", "m68ap", "kernelcache.release.s5l8900x"),
					testBuildIdentity("iPhone1,2", "n82ap", "kernelcache.release.s5l8900x"),
				},
			},
		},
	}

	kernels := inf.GetKernelCacheForDevice("iPhone1,2")
	wantKernels := []string{"kernelcache.release.s5l8900x"}
	if !slices.Equal(kernels, wantKernels) {
		t.Fatalf("GetKernelCacheForDevice() = %#v, want %#v", kernels, wantKernels)
	}

	devices := inf.GetDevicesForKernelCache("kernelcache.release.s5l8900x")
	wantDevices := []string{"iPhone1,1", "iPhone1,2"}
	if !slices.Equal(devices, wantDevices) {
		t.Fatalf("GetDevicesForKernelCache() = %#v, want %#v", devices, wantDevices)
	}
}

func testBuildIdentity(productType, deviceClass, kernelPath string) plist.BuildIdentity {
	return plist.BuildIdentity{
		ApProductType: productType,
		Info: plist.IdentityInfo{
			DeviceClass: deviceClass,
		},
		Manifest: map[string]plist.IdentityManifest{
			"KernelCache": {
				Info: map[string]any{
					"Path": kernelPath,
				},
			},
		},
	}
}
