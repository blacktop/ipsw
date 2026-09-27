package dyld

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func TestObjCModeAndImageConfigKeysDoNotCollide(t *testing.T) {
	for _, tc := range []struct {
		mode string
		cmd  *cobra.Command
	}{
		{"class", objcClassCmd}, {"sel", objcSelCmd}, {"proto", objcProtoCmd},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			modeFlag := ObjcCmd.Flags().Lookup(tc.mode)
			imageFlag := tc.cmd.Flags().Lookup("image")
			modeValue, modeChanged := modeFlag.Value.String(), modeFlag.Changed
			imageValue, imageChanged := imageFlag.Value.String(), imageFlag.Changed
			t.Cleanup(func() {
				modeFlag.Value.Set(modeValue)
				modeFlag.Changed = modeChanged
				imageFlag.Value.Set(imageValue)
				imageFlag.Changed = imageChanged
			})
			if err := ObjcCmd.Flags().Set(tc.mode, "true"); err != nil {
				t.Fatal(err)
			}
			if err := tc.cmd.Flags().Set("image", "libSynthetic.dylib"); err != nil {
				t.Fatal(err)
			}
			// Materializing settings used to lose either the scalar mode or
			// the image subtree, depending on map iteration order.
			for range 20 {
				settings := viper.New()
				if err := settings.MergeConfigMap(viper.AllSettings()); err != nil {
					t.Fatal(err)
				}
				if !settings.GetBool("dyld.objc.dump-"+tc.mode) || settings.GetString("dyld.objc."+tc.mode+".image") != "libSynthetic.dylib" {
					t.Fatalf("ObjC mode or image lost during settings materialization: %v", settings.Get("dyld.objc"))
				}
			}
		})
	}
}

func TestObjCDumpModePreservesLegacyConfigAndFlagPrecedence(t *testing.T) {
	for _, mode := range []string{"class", "sel", "proto"} {
		t.Run(mode, func(t *testing.T) {
			flag := ObjcCmd.Flags().Lookup(mode)
			value, changed := flag.Value.String(), flag.Changed
			t.Cleanup(func() {
				flag.Value.Set(value)
				flag.Changed = changed
				viper.Set("dyld.objc."+mode, nil)
				viper.Set("dyld.objc.dump-"+mode, nil)
			})

			// Released config keys keep working.
			viper.Set("dyld.objc."+mode, true)
			if !objcDumpMode(mode) {
				t.Fatalf("legacy key dyld.objc.%s=true ignored", mode)
			}
			viper.Set("dyld.objc."+mode, false)
			if objcDumpMode(mode) {
				t.Fatalf("legacy key dyld.objc.%s=false enabled dump", mode)
			}

			// A subcommand image subtree under the same key is not a request to dump.
			viper.Set("dyld.objc."+mode, map[string]any{"image": "libSynthetic.dylib"})
			if objcDumpMode(mode) {
				t.Fatalf("image subtree under dyld.objc.%s enabled dump", mode)
			}

			// The dump-* key wins over the legacy scalar in both directions.
			viper.Set("dyld.objc."+mode, true)
			viper.Set("dyld.objc.dump-"+mode, false)
			if objcDumpMode(mode) {
				t.Fatalf("dump-%s=false did not override legacy true", mode)
			}
			viper.Set("dyld.objc."+mode, false)
			viper.Set("dyld.objc.dump-"+mode, true)
			if !objcDumpMode(mode) {
				t.Fatalf("dump-%s=true did not override legacy false", mode)
			}

			// An explicit flag is bound to the dump-* key and therefore wins too.
			viper.Set("dyld.objc.dump-"+mode, nil)
			viper.Set("dyld.objc."+mode, false)
			if err := ObjcCmd.Flags().Set(mode, "true"); err != nil {
				t.Fatal(err)
			}
			if !objcDumpMode(mode) {
				t.Fatalf("--%s flag did not enable dump", mode)
			}
		})
	}
}
