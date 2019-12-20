package macho

import "strings"

type headerFlags uint32

const (
	FlagNoUndefs                   headerFlags = 0x1
	FlagIncrLink                   headerFlags = 0x2
	FlagDyldLink                   headerFlags = 0x4
	FlagBindAtLoad                 headerFlags = 0x8
	FlagPrebound                   headerFlags = 0x10
	FlagSplitSegs                  headerFlags = 0x20
	FlagLazyInit                   headerFlags = 0x40
	FlagTwoLevel                   headerFlags = 0x80
	FlagForceFlat                  headerFlags = 0x100
	FlagNoMultiDefs                headerFlags = 0x200
	FlagNoFixPrebinding            headerFlags = 0x400
	FlagPrebindable                headerFlags = 0x800
	FlagAllModsBound               headerFlags = 0x1000
	FlagSubsectionsViaSymbols      headerFlags = 0x2000
	FlagCanonical                  headerFlags = 0x4000
	FlagWeakDefines                headerFlags = 0x8000
	FlagBindsToWeak                headerFlags = 0x10000
	FlagAllowStackExecution        headerFlags = 0x20000
	FlagRootSafe                   headerFlags = 0x40000
	FlagSetuidSafe                 headerFlags = 0x80000
	FlagNoReexportedDylibs         headerFlags = 0x100000
	FlagPIE                        headerFlags = 0x200000
	FlagDeadStrippableDylib        headerFlags = 0x400000
	FlagHasTLVDescriptors          headerFlags = 0x800000
	FlagNoHeapExecution            headerFlags = 0x1000000
	FlagAppExtensionSafe           headerFlags = 0x2000000
	FlagNlistOutofsyncWithDyldinfo headerFlags = 0x4000000
	FlagSimSupport                 headerFlags = 0x8000000
	FlagDylibInCache               headerFlags = 0x80000000
)

func (f headerFlags) NoUndefs() bool {
	return (f & FlagNoUndefs) != 0
}
func (f headerFlags) IncrLink() bool {
	return (f & FlagIncrLink) != 0
}
func (f headerFlags) DyldLink() bool {
	return (f & FlagDyldLink) != 0
}
func (f headerFlags) BindAtLoad() bool {
	return (f & FlagBindAtLoad) != 0
}
func (f headerFlags) Prebound() bool {
	return (f & FlagPrebound) != 0
}
func (f headerFlags) SplitSegs() bool {
	return (f & FlagSplitSegs) != 0
}
func (f headerFlags) LazyInit() bool {
	return (f & FlagLazyInit) != 0
}
func (f headerFlags) TwoLevel() bool {
	return (f & FlagTwoLevel) != 0
}
func (f headerFlags) ForceFlat() bool {
	return (f & FlagForceFlat) != 0
}
func (f headerFlags) NoMultiDefs() bool {
	return (f & FlagNoMultiDefs) != 0
}
func (f headerFlags) NoFixPrebinding() bool {
	return (f & FlagNoFixPrebinding) != 0
}
func (f headerFlags) Prebindable() bool {
	return (f & FlagPrebindable) != 0
}
func (f headerFlags) AllModsBound() bool {
	return (f & FlagAllModsBound) != 0
}
func (f headerFlags) SubsectionsViaSymbols() bool {
	return (f & FlagSubsectionsViaSymbols) != 0
}
func (f headerFlags) Canonical() bool {
	return (f & FlagCanonical) != 0
}
func (f headerFlags) WeakDefines() bool {
	return (f & FlagWeakDefines) != 0
}
func (f headerFlags) BindsToWeak() bool {
	return (f & FlagBindsToWeak) != 0
}
func (f headerFlags) AllowStackExecution() bool {
	return (f & FlagAllowStackExecution) != 0
}
func (f headerFlags) RootSafe() bool {
	return (f & FlagRootSafe) != 0
}
func (f headerFlags) SetuidSafe() bool {
	return (f & FlagSetuidSafe) != 0
}
func (f headerFlags) NoReexportedDylibs() bool {
	return (f & FlagNoReexportedDylibs) != 0
}
func (f headerFlags) PIE() bool {
	return (f & FlagPIE) != 0
}
func (f headerFlags) DeadStrippableDylib() bool {
	return (f & FlagDeadStrippableDylib) != 0
}
func (f headerFlags) HasTLVDescriptors() bool {
	return (f & FlagHasTLVDescriptors) != 0
}
func (f headerFlags) NoHeapExecution() bool {
	return (f & FlagNoHeapExecution) != 0
}
func (f headerFlags) AppExtensionSafe() bool {
	return (f & FlagAppExtensionSafe) != 0
}
func (f headerFlags) NlistOutofsyncWithDyldinfo() bool {
	return (f & FlagNlistOutofsyncWithDyldinfo) != 0
}
func (f headerFlags) SimSupport() bool {
	return (f & FlagSimSupport) != 0
}
func (f headerFlags) DylibInCache() bool {
	return (f & FlagDylibInCache) != 0
}

func (fs headerFlags) String() string {
	var fStr string
	if fs.NoUndefs() {
		fStr += "NoUndefs "
	}
	if fs.IncrLink() {
		fStr += "IncrLink "
	}
	if fs.DyldLink() {
		fStr += "DyldLink "
	}
	if fs.BindAtLoad() {
		fStr += "BindAtLoad "
	}
	if fs.Prebound() {
		fStr += "Prebound "
	}
	if fs.SplitSegs() {
		fStr += "SplitSegs "
	}
	if fs.LazyInit() {
		fStr += "LazyInit "
	}
	if fs.TwoLevel() {
		fStr += "TwoLevel "
	}
	if fs.ForceFlat() {
		fStr += "ForceFlat "
	}
	if fs.NoMultiDefs() {
		fStr += "NoMultiDefs "
	}
	if fs.NoFixPrebinding() {
		fStr += "NoFixPrebinding "
	}
	if fs.Prebindable() {
		fStr += "Prebindable "
	}
	if fs.AllModsBound() {
		fStr += "AllModsBound "
	}
	if fs.SubsectionsViaSymbols() {
		fStr += "SubsectionsViaSymbols "
	}
	if fs.Canonical() {
		fStr += "Canonical "
	}
	if fs.WeakDefines() {
		fStr += "WeakDefines "
	}
	if fs.BindsToWeak() {
		fStr += "BindsToWeak "
	}
	if fs.AllowStackExecution() {
		fStr += "AllowStackExecution "
	}
	if fs.RootSafe() {
		fStr += "RootSafe "
	}
	if fs.SetuidSafe() {
		fStr += "SetuidSafe "
	}
	if fs.NoReexportedDylibs() {
		fStr += "NoReexportedDylibs "
	}
	if fs.PIE() {
		fStr += "PIE "
	}
	if fs.DeadStrippableDylib() {
		fStr += "DeadStrippableDylib "
	}
	if fs.HasTLVDescriptors() {
		fStr += "HasTLVDescriptors "
	}
	if fs.NoHeapExecution() {
		fStr += "NoHeapExecution "
	}
	if fs.AppExtensionSafe() {
		fStr += "AppExtensionSafe "
	}
	if fs.NlistOutofsyncWithDyldinfo() {
		fStr += "NlistOutofsyncWithDyldinfo "
	}
	if fs.SimSupport() {
		fStr += "SimSupport "
	}
	if fs.DylibInCache() {
		fStr += "DylibInCache "
	}
	return strings.TrimSpace(fStr)
}
