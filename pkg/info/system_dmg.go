package info

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/blacktop/ipsw/pkg/plist"
)

// ErrAmbiguousSystemOS reports that the selected build identities still span
// more than one SystemOS image. The message names the images and their
// targets; commands that expose a device selector add the flag hint.
var ErrAmbiguousSystemOS = errors.New("multiple SystemOS DMGs found")

// SystemOSDMG describes one distinct SystemOS image and its manifest targets.
type SystemOSDMG struct {
	Path    string   `json:"path"`
	Devices []string `json:"devices,omitempty"`
	Boards  []string `json:"boards,omitempty"`
}

// String renders the image path followed by its product types, or its boards
// when the manifest identities carry no product type.
func (d SystemOSDMG) String() string {
	targets := d.Devices
	if len(targets) == 0 {
		targets = d.Boards
	}
	if len(targets) == 0 {
		return d.Path
	}
	return fmt.Sprintf("%s [%s]", d.Path, strings.Join(targets, ", "))
}

// GetSystemOsDmgs enumerates distinct images in BuildManifest order, retaining
// their device associations instead of treating repeated install variants as images.
func (i *Info) GetSystemOsDmgs() ([]SystemOSDMG, error) {
	if i == nil || i.Plists == nil || i.Plists.BuildManifest == nil {
		return nil, fmt.Errorf("no SystemOS DMG found: no BuildManifest.plist: %w", ErrorCryptexNotFound)
	}
	var out []SystemOSDMG
	for _, bi := range i.Plists.BuildIdentities {
		component, ok := bi.Manifest["Cryptex1,SystemOS"]
		if !ok {
			continue
		}
		path, ok := getIdentityManifestPath(component)
		if !ok {
			return nil, fmt.Errorf("invalid SystemOS path for device class %q", bi.Info.DeviceClass)
		}
		idx := slices.IndexFunc(out, func(d SystemOSDMG) bool { return d.Path == path })
		if idx < 0 {
			idx = len(out)
			out = append(out, SystemOSDMG{Path: path})
		}
		dmg := &out[idx]
		product := i.identityProduct(bi)
		if product != "" && !slices.Contains(dmg.Devices, product) {
			dmg.Devices = append(dmg.Devices, product)
		}
		if bi.Info.DeviceClass != "" && !slices.Contains(dmg.Boards, bi.Info.DeviceClass) {
			dmg.Boards = append(dmg.Boards, bi.Info.DeviceClass)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no SystemOS DMG found: %w", ErrorCryptexNotFound)
	}
	return out, nil
}

func (i *Info) identityProduct(bi plist.BuildIdentity) string {
	if bi.ApProductType != "" {
		return bi.ApProductType
	}
	if len(i.Plists.BuildManifest.SupportedProductTypes) == 1 {
		return i.Plists.BuildManifest.SupportedProductTypes[0]
	}
	if bi.Info.DeviceClass != "" {
		for _, tree := range i.DeviceTrees {
			if tree == nil {
				continue
			}
			if dt, err := tree.Summary(); err == nil && strings.EqualFold(dt.BoardConfig, bi.Info.DeviceClass) && dt.ProductType != "" {
				return dt.ProductType
			}
		}
	}
	return ""
}

// ForDevice returns a shallow metadata copy with only the selected build
// identities. device is an exact, case-insensitive product type or device class.
// The source metadata is never modified. Empty device leaves it unfiltered.
func (i *Info) ForDevice(device string) (*Info, error) {
	if device == "" {
		return i, nil
	}
	if i == nil || i.Plists == nil || i.Plists.BuildManifest == nil {
		return nil, fmt.Errorf("cannot select device %q: no BuildManifest.plist found", device)
	}
	var identities []plist.BuildIdentity
	for _, bi := range i.Plists.BuildIdentities {
		if strings.EqualFold(device, i.identityProduct(bi)) || strings.EqualFold(device, bi.Info.DeviceClass) {
			identities = append(identities, bi)
		}
	}
	if len(identities) == 0 {
		return nil, fmt.Errorf("no BuildManifest identity matches device %q (use a product type or device class)", device)
	}
	copyInfo := *i
	copyPlists := *i.Plists
	copyManifest := *i.Plists.BuildManifest
	copyManifest.BuildIdentities = identities
	copyPlists.BuildManifest = &copyManifest
	if copyPlists.SelectedFrom == nil {
		copyPlists.SelectedFrom = i.Plists.BuildManifest
	}
	copyInfo.Plists = &copyPlists
	return &copyInfo, nil
}

// ProductType resolves a board (device class) selector to the product type of
// the first matching build identity. Product types and unknown selectors are
// returned unchanged so product-type lookups keep reporting their own errors.
func (i *Info) ProductType(device string) string {
	if device == "" {
		return device
	}
	selected, err := i.ForDevice(device)
	if err != nil {
		return device
	}
	for _, bi := range selected.Plists.BuildIdentities {
		if product := i.identityProduct(bi); product != "" {
			return product
		}
	}
	return device
}

// SelectDevice applies ForDevice and then rejects metadata whose SystemOS image
// is still ambiguous, so callers fail before extracting or mounting anything
// instead of silently skipping the SystemOS volume. A missing SystemOS
// (ErrorCryptexNotFound) is not an error here; pre-cryptex IPSWs are valid.
func (i *Info) SelectDevice(device string) (*Info, error) {
	selected, err := i.ForDevice(device)
	if err != nil {
		return nil, err
	}
	if _, err := selected.GetSystemOsDmg(); err != nil && !errors.Is(err, ErrorCryptexNotFound) {
		return nil, err
	}
	return selected, nil
}

// SelectDeviceOrSharedSystem allows comparison or symbolication against older
// firmware that predates a device, but only when its SystemOS is unambiguous.
// Fallback leaves all identities intact; consumers of other components must
// validate those components separately (a shared SystemOS need not share a kernel).
// Explicit extraction and scanning should keep using SelectDevice.
func (i *Info) SelectDeviceOrSharedSystem(device string) (*Info, error) {
	selected, err := i.ForDevice(device)
	if err == nil {
		return selected.SelectDevice("")
	}
	if _, sharedErr := i.GetSystemOsDmg(); sharedErr == nil {
		return i, nil
	}
	return nil, err
}

// GetSystemOsDmg returns the unique SystemOS image in the selected identities.
// Use ForDevice to select a target when an IPSW contains multiple images.
func (i *Info) GetSystemOsDmg() (string, error) {
	dmgs, err := i.GetSystemOsDmgs()
	if err != nil {
		return "", err
	}
	if len(dmgs) == 1 {
		return dmgs[0].Path, nil
	}
	choices := make([]string, 0, len(dmgs))
	for _, d := range dmgs {
		choices = append(choices, d.String())
	}
	return "", fmt.Errorf("%w; select a device (product type or board): %s",
		ErrAmbiguousSystemOS, strings.Join(choices, "; "))
}
