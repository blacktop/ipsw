package diff

import (
	"path/filepath"
	"testing"

	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/internal/testutil"
)

func TestEntsJobIgnoresFatOrder(t *testing.T) {
	const want = `<plist version="1.0"><dict><key>synthetic.preferred</key><true/></dict></plist>`
	const other = `<plist version="1.0"><dict><key>synthetic.other</key><true/></dict></plist>`
	x1 := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64EX1, Entitlements: want}
	e := testutil.MachoArch{CPU: types.CPUArm64, SubCPU: types.CPUSubtypeArm64E, Entitlements: other}
	intel := testutil.MachoArch{CPU: types.CPUAmd64, SubCPU: types.CPUSubtypeX8664All, Entitlements: other}
	for _, arches := range [][]testutil.MachoArch{{x1, e, intel}, {intel, x1, e}, {e, intel, x1}} {
		oldRoot, newRoot := t.TempDir(), t.TempDir()
		testutil.WriteMacho(t, filepath.Join(oldRoot, "tool"), arches...)
		testutil.WriteMacho(t, filepath.Join(newRoot, "tool"), x1)
		job := newEntitlementsJob(&Diff{conf: &Config{}})
		if errs := runVolumeTasks("fs", volumeRoots{old: oldRoot, new: newRoot}, []Task{job}); len(errs) != 0 {
			t.Fatal(errs)
		}
		for _, bucket := range []map[string]string{job.prevByVolume[volumeLabel("fs")], job.nextByVolume[volumeLabel("fs")]} {
			if got := bucket["/tool"]; got != want {
				t.Errorf("entitlement scan = %q, want %q", got, want)
			}
		}
		if err := job.Finalize(); err != nil {
			t.Fatal(err)
		}
		if len(job.d.Ents) != 0 {
			t.Errorf("architecture order produced an entitlement diff: %v", job.d.Ents)
		}
	}
}
