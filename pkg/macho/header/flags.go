package header

import (
	"fmt"
	"strings"
)

type Flag uint32

const (
	NoUndefs                   Flag = 0x1
	IncrLink                   Flag = 0x2
	DyldLink                   Flag = 0x4
	BindAtLoad                 Flag = 0x8
	Prebound                   Flag = 0x10
	SplitSegs                  Flag = 0x20
	LazyInit                   Flag = 0x40
	TwoLevel                   Flag = 0x80
	ForceFlat                  Flag = 0x100
	NoMultiDefs                Flag = 0x200
	NoFixPrebinding            Flag = 0x400
	Prebindable                Flag = 0x800
	AllModsBound               Flag = 0x1000
	SubsectionsViaSymbols      Flag = 0x2000
	Canonical                  Flag = 0x4000
	WeakDefines                Flag = 0x8000
	BindsToWeak                Flag = 0x10000
	AllowStackExecution        Flag = 0x20000
	RootSafe                   Flag = 0x40000
	SetuidSafe                 Flag = 0x80000
	NoReexportedDylibs         Flag = 0x100000
	PIE                        Flag = 0x200000
	DeadStrippableDylib        Flag = 0x400000
	HasTLVDescriptors          Flag = 0x800000
	NoHeapExecution            Flag = 0x1000000
	AppExtensionSafe           Flag = 0x2000000
	NlistOutofsyncWithDyldinfo Flag = 0x4000000
	SimSupport                 Flag = 0x8000000
	DylibInCache               Flag = 0x80000000
)

///GETTERS
func (f Flag) NoUndefs() bool {
	return (f & NoUndefs) != 0
}
func (f Flag) IncrLink() bool {
	return (f & IncrLink) != 0
}
func (f Flag) DyldLink() bool {
	return (f & DyldLink) != 0
}
func (f Flag) BindAtLoad() bool {
	return (f & BindAtLoad) != 0
}
func (f Flag) Prebound() bool {
	return (f & Prebound) != 0
}
func (f Flag) SplitSegs() bool {
	return (f & SplitSegs) != 0
}
func (f Flag) LazyInit() bool {
	return (f & LazyInit) != 0
}
func (f Flag) TwoLevel() bool {
	return (f & TwoLevel) != 0
}
func (f Flag) ForceFlat() bool {
	return (f & ForceFlat) != 0
}
func (f Flag) NoMultiDefs() bool {
	return (f & NoMultiDefs) != 0
}
func (f Flag) NoFixPrebinding() bool {
	return (f & NoFixPrebinding) != 0
}
func (f Flag) Prebindable() bool {
	return (f & Prebindable) != 0
}
func (f Flag) AllModsBound() bool {
	return (f & AllModsBound) != 0
}
func (f Flag) SubsectionsViaSymbols() bool {
	return (f & SubsectionsViaSymbols) != 0
}
func (f Flag) Canonical() bool {
	return (f & Canonical) != 0
}
func (f Flag) WeakDefines() bool {
	return (f & WeakDefines) != 0
}
func (f Flag) BindsToWeak() bool {
	return (f & BindsToWeak) != 0
}
func (f Flag) AllowStackExecution() bool {
	return (f & AllowStackExecution) != 0
}
func (f Flag) RootSafe() bool {
	return (f & RootSafe) != 0
}
func (f Flag) SetuidSafe() bool {
	return (f & SetuidSafe) != 0
}
func (f Flag) NoReexportedDylibs() bool {
	return (f & NoReexportedDylibs) != 0
}
func (f Flag) PIE() bool {
	return (f & PIE) != 0
}
func (f Flag) DeadStrippableDylib() bool {
	return (f & DeadStrippableDylib) != 0
}
func (f Flag) HasTLVDescriptors() bool {
	return (f & HasTLVDescriptors) != 0
}
func (f Flag) NoHeapExecution() bool {
	return (f & NoHeapExecution) != 0
}
func (f Flag) AppExtensionSafe() bool {
	return (f & AppExtensionSafe) != 0
}
func (f Flag) NlistOutofsyncWithDyldinfo() bool {
	return (f & NlistOutofsyncWithDyldinfo) != 0
}
func (f Flag) SimSupport() bool {
	return (f & SimSupport) != 0
}
func (f Flag) DylibInCache() bool {
	return (f & DylibInCache) != 0
}

///SETTER
func (f *Flag) Set(flag Flag, set bool) {
	if set {
		*f = (*f | flag)
	} else {
		*f = (*f ^ flag)
	}
}

// List returns a string array of flag names
func (f Flag) List() []string {
	var flags []string
	if f.NoUndefs() {
		flags = append(flags, NoUndefs.String())
	}
	if f.IncrLink() {
		flags = append(flags, IncrLink.String())
	}
	if f.DyldLink() {
		flags = append(flags, DyldLink.String())
	}
	if f.BindAtLoad() {
		flags = append(flags, BindAtLoad.String())
	}
	if f.Prebound() {
		flags = append(flags, Prebound.String())
	}
	if f.SplitSegs() {
		flags = append(flags, SplitSegs.String())
	}
	if f.LazyInit() {
		flags = append(flags, LazyInit.String())
	}
	if f.TwoLevel() {
		flags = append(flags, TwoLevel.String())
	}
	if f.ForceFlat() {
		flags = append(flags, ForceFlat.String())
	}
	if f.NoMultiDefs() {
		flags = append(flags, NoMultiDefs.String())
	}
	if f.NoFixPrebinding() {
		flags = append(flags, NoFixPrebinding.String())
	}
	if f.Prebindable() {
		flags = append(flags, Prebindable.String())
	}
	if f.AllModsBound() {
		flags = append(flags, AllModsBound.String())
	}
	if f.SubsectionsViaSymbols() {
		flags = append(flags, SubsectionsViaSymbols.String())
	}
	if f.Canonical() {
		flags = append(flags, Canonical.String())
	}
	if f.WeakDefines() {
		flags = append(flags, WeakDefines.String())
	}
	if f.BindsToWeak() {
		flags = append(flags, BindsToWeak.String())
	}
	if f.AllowStackExecution() {
		flags = append(flags, AllowStackExecution.String())
	}
	if f.RootSafe() {
		flags = append(flags, RootSafe.String())
	}
	if f.SetuidSafe() {
		flags = append(flags, SetuidSafe.String())
	}
	if f.NoReexportedDylibs() {
		flags = append(flags, NoReexportedDylibs.String())
	}
	if f.PIE() {
		flags = append(flags, PIE.String())
	}
	if f.DeadStrippableDylib() {
		flags = append(flags, DeadStrippableDylib.String())
	}
	if f.HasTLVDescriptors() {
		flags = append(flags, HasTLVDescriptors.String())
	}
	if f.NoHeapExecution() {
		flags = append(flags, NoHeapExecution.String())
	}
	if f.AppExtensionSafe() {
		flags = append(flags, AppExtensionSafe.String())
	}
	if f.NlistOutofsyncWithDyldinfo() {
		flags = append(flags, NlistOutofsyncWithDyldinfo.String())
	}
	if f.SimSupport() {
		flags = append(flags, SimSupport.String())
	}
	if f.DylibInCache() {
		flags = append(flags, DylibInCache.String())
	}
	return flags
}

func (f Flag) Flags() string {
	var fStr string
	for _, attr := range f.List() {
		fStr += fmt.Sprintf("%s, ", attr)
	}
	return strings.TrimSuffix(fStr, ", ")
}
