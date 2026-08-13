package ai

import (
	"errors"
	"testing"

	model "github.com/blacktop/ipsw/internal/model/ai"
)

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

func TestOrcaRouterUsesVersionedModelsCache(t *testing.T) {
	if got := modelsCacheKeyForProvider("orcarouter"); got != orcarouterTextChatModelsCacheKey {
		t.Fatalf("modelsCacheKeyForProvider(orcarouter) = %q, want %q", got, orcarouterTextChatModelsCacheKey)
	}
	if got := modelsCacheKeyForProvider("openrouter"); got != "openrouter" {
		t.Fatalf("modelsCacheKeyForProvider(openrouter) = %q, want openrouter", got)
	}
}

func TestOrcaRouterModelCacheOperationsUseVersionedKey(t *testing.T) {
	cache := &recordingCache{}
	client := &CachingAI{
		ai: &stubAI{
			models:  map[string]string{"openai/gpt-5.5": "openai/gpt-5.5"},
			chatErr: errors.New("request failed with status 400"),
		},
		cache:          cache,
		config:         &Config{Provider: "orcarouter"},
		modelsCacheKey: modelsCacheKeyForProvider("orcarouter"),
	}

	if _, err := client.Models(); err != nil {
		t.Fatalf("Models() error = %v", err)
	}
	if cache.getModelsKey != orcarouterTextChatModelsCacheKey {
		t.Fatalf("GetProviderModels key = %q, want %q", cache.getModelsKey, orcarouterTextChatModelsCacheKey)
	}
	if cache.setModelsKey != orcarouterTextChatModelsCacheKey {
		t.Fatalf("SetProviderModels key = %q, want %q", cache.setModelsKey, orcarouterTextChatModelsCacheKey)
	}

	if _, err := client.Chat(); err == nil {
		t.Fatal("Chat() error = nil, want model error")
	}
	if cache.deleteModelsKey != orcarouterTextChatModelsCacheKey {
		t.Fatalf("DeleteProviderModels key = %q, want %q", cache.deleteModelsKey, orcarouterTextChatModelsCacheKey)
	}
}

type stubAI struct {
	models  map[string]string
	chatErr error
}

func (s *stubAI) Chat() (string, error) {
	return "", s.chatErr
}

func (s *stubAI) Models() (map[string]string, error) {
	return s.models, nil
}

func (s *stubAI) SetModels(models map[string]string) (map[string]string, error) {
	s.models = models
	return s.models, nil
}

func (s *stubAI) SetModel(string) error {
	return nil
}

func (s *stubAI) Verify() error {
	return nil
}

func (s *stubAI) Close() error {
	return nil
}

type recordingCache struct {
	getModelsKey    string
	setModelsKey    string
	deleteModelsKey string
}

func (c *recordingCache) Get(string, string, string, string, float64, float64) (*model.ChatResponse, error) {
	return nil, model.ErrNotFound
}

func (c *recordingCache) Set(*model.ChatResponse) error {
	return nil
}

func (c *recordingCache) GetProviderModels(provider string) (*model.ProviderModels, error) {
	c.getModelsKey = provider
	return nil, model.ErrNotFound
}

func (c *recordingCache) SetProviderModels(models *model.ProviderModels) error {
	c.setModelsKey = models.Provider
	return nil
}

func (c *recordingCache) DeleteProviderModels(provider string) error {
	c.deleteModelsKey = provider
	return nil
}

func (c *recordingCache) Close() error {
	return nil
}
