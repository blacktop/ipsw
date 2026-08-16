package dyld

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	dyldpkg "github.com/blacktop/ipsw/pkg/dyld"
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

type fakeDscFuncImageResolver struct {
	textImage *dyldpkg.CacheImage
	textErr   error
	nameCalls int
}

func (f *fakeDscFuncImageResolver) GetImageContainingTextAddr(uint64) (*dyldpkg.CacheImage, error) {
	if f.textErr != nil {
		return nil, f.textErr
	}
	return f.textImage, nil
}

func (f *fakeDscFuncImageResolver) GetImageContainingVMAddr(uint64) (*dyldpkg.CacheImage, error) {
	return nil, errors.New("not in VM")
}

func (f *fakeDscFuncImageResolver) Image(string) (*dyldpkg.CacheImage, error) {
	f.nameCalls++
	return nil, errors.New("ambiguous basename")
}

func TestResolveDscFuncImagePrefersStartAddress(t *testing.T) {
	expected := &dyldpkg.CacheImage{Name: "/System/Library/PrivateFrameworks/HomeUI.framework/HomeUI"}
	resolver := &fakeDscFuncImageResolver{
		textImage: expected,
	}

	got, err := resolveDscFuncImage(resolver, dscFunc{
		Start: 0x20cfc324c,
		Image: "HomeUI",
	})
	if err != nil {
		t.Fatalf("resolveDscFuncImage returned error: %v", err)
	}
	if got != expected {
		t.Fatalf("expected image %q, got %#v", expected.Name, got)
	}
	if resolver.nameCalls != 0 {
		t.Fatalf("expected start-address resolution to avoid basename lookup, called Image %d times", resolver.nameCalls)
	}
}

func TestFilterImportRowsUsesRegex(t *testing.T) {
	t.Parallel()

	filter, err := compileImportsFilter(`xmlXPath|xmlSchema`)
	if err != nil {
		t.Fatalf("compileImportsFilter failed: %v", err)
	}
	rows := []string{
		"_objc_msgSend",
		"_xmlXPathNewContext",
		"_xmlSchemaFreeValidCtxt",
	}

	got := filterImportRows(rows, filter)
	want := []string{"_xmlXPathNewContext", "_xmlSchemaFreeValidCtxt"}
	if !slices.Equal(got, want) {
		t.Fatalf("filterImportRows=%#v, want %#v", got, want)
	}
}

func TestSymAddrPreservesAutoDetectedNoColor(t *testing.T) {
	previousNoColor := color.NoColor
	previousColorSetting := viper.Get("color")
	previousNoColorSetting := viper.Get("no-color")
	t.Cleanup(func() {
		color.NoColor = previousNoColor
		viper.Set("color", previousColorSetting)
		viper.Set("no-color", previousNoColorSetting)
	})

	color.NoColor = true
	viper.Set("color", true)
	viper.Set("no-color", false)

	err := SymAddrCmd.RunE(SymAddrCmd, []string{filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("expected missing DSC to return an error")
	}
	if !color.NoColor {
		t.Fatal("symaddr enabled color after stdout was detected as non-terminal")
	}
}
