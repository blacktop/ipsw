package diff

import "testing"

// TestTopLevelTasksAreCacheable documents that every top-level task implements
// CacheableTask so a fully-cached warm rerun runs ZERO top-level Parse work. A
// type assertion guards against an accidental future opt-out that would silently
// reintroduce uncached parse work on a warm rerun.
func TestTopLevelTasksAreCacheable(t *testing.T) {
	for name, task := range map[string]Task{
		"kexts":     &kextsTask{},
		"iboot":     &ibootTask{},
		"kdks":      &kdksTask{},
		"firmwares": &firmwaresTask{},
		"sandbox":   &sandboxTask{},
	} {
		if _, ok := task.(CacheableTask); !ok {
			t.Errorf("%s must implement CacheableTask", name)
		}
	}
}
