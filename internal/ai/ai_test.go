package ai

import "testing"

func TestCopilotProviderAvailable(t *testing.T) {
	if !IsValidProvider("copilot") {
		t.Fatal("copilot must be exposed as a supported provider")
	}
}

func TestOrcaRouterProviderAvailable(t *testing.T) {
	if !IsValidProvider("orcarouter") {
		t.Fatal("orcarouter must be exposed as a supported provider")
	}
}
