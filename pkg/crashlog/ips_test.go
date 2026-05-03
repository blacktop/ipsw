package crashlog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestIPSPayloadTrialInfoFactorPackIdsArray(t *testing.T) {
	var payload IPSPayload
	data := []byte(`{
		"trialInfo": {
			"rollouts": [
				{
					"rolloutId": "66d35d7fe4d6bf7664f40ddf",
					"factorPackIds": ["68c1a34bd359577bbe8f2182"],
					"deploymentId": 240000067
				}
			]
		}
	}`)

	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	rollouts := payload.TrialInfo.Rollouts
	if len(rollouts) != 1 {
		t.Fatalf("expected 1 rollout, got %d", len(rollouts))
	}
	assertFactorPackIDs(t, rollouts[0].FactorPackIds, "68c1a34bd359577bbe8f2182")
}

func TestOpenIPSAcceptsTrialInfoFactorPackIdsArray(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ios26.ips")
	data := []byte(`{"bug_type":"309","os_version":"iPhone OS 26.0 (23A000)"}
{
	"modelCode": "iPhone17,1",
	"trialInfo": {
		"rollouts": [
			{
				"rolloutId": "66d35d7fe4d6bf7664f40ddf",
				"factorPackIds": ["68c1a34bd359577bbe8f2182"],
				"deploymentId": 240000067
			}
		]
	}
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	ips, err := OpenIPS(path, &Config{})
	if err != nil {
		t.Fatalf("OpenIPS: %v", err)
	}

	rollouts := ips.Payload.TrialInfo.Rollouts
	if len(rollouts) != 1 {
		t.Fatalf("expected 1 rollout, got %d", len(rollouts))
	}
	assertFactorPackIDs(t, rollouts[0].FactorPackIds, "68c1a34bd359577bbe8f2182")
}

func TestIPSPayloadTrialInfoFactorPackIdsLegacyObject(t *testing.T) {
	var payload IPSPayload
	data := []byte(`{
		"trialInfo": {
			"rollouts": [
				{
					"rolloutId": "66d35d7fe4d6bf7664f40ddf",
					"factorPackIds": {},
					"deploymentId": 240000067
				}
			]
		}
	}`)

	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	rollouts := payload.TrialInfo.Rollouts
	if len(rollouts) != 1 {
		t.Fatalf("expected 1 rollout, got %d", len(rollouts))
	}
	assertFactorPackIDs(t, rollouts[0].FactorPackIds)
}

func TestFactorPackIdsRejectsInvalidShape(t *testing.T) {
	var factorPackIDs FactorPackIDs
	if err := json.Unmarshal([]byte(`"68c1a34bd359577bbe8f2182"`), &factorPackIDs); err == nil {
		t.Fatal("expected invalid scalar factorPackIds to fail")
	}
}

func assertFactorPackIDs(t *testing.T, got FactorPackIDs, want ...string) {
	t.Helper()

	if !slices.Equal(got, want) {
		t.Fatalf("unexpected factor pack IDs: got %#v, want %#v", got, want)
	}
}
