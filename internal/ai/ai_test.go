package ai

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	model "github.com/blacktop/ipsw/internal/model/ai"
)

func TestCompatibleProviderUsesEndpointScopedCaches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/models"):
			fmt.Fprint(w, `{"data":[{"id":"test-model"}]}`)
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			fmt.Fprint(w, `{"choices":[{"message":{"content":"test response"}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("OPENAI_BASE_URL", server.URL+"/first/v1")
	t.Setenv("OPENAI_API_KEY", "test-key")
	var firstModelsKey, firstChatKey string
	for _, endpoint := range []string{"", server.URL + "/second/v1"} {
		cfg := &Config{Provider: "openai-compatible", BaseURL: endpoint, Model: "test-model", DisableCache: true}
		client, err := NewAI(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		cached, ok := client.(*CachingAI)
		if !ok {
			t.Fatal("NewAI did not return CachingAI")
		}
		cache := &recordingCache{}
		cached.cache = cache
		cfg.DisableCache = false
		if _, err := cached.Models(); err != nil {
			t.Fatal(err)
		}
		if _, err := cached.Chat(); err != nil {
			t.Fatal(err)
		}
		if cache.getModelsKey != cached.modelsCacheKey || cache.setModelsKey != cached.modelsCacheKey || cache.getChatKey != cached.chatCacheKey || cache.setChatKey != cached.chatCacheKey {
			t.Fatalf("cache operations used incorrect identity: %+v", cache)
		}
		if endpoint == "" {
			firstModelsKey, firstChatKey = cached.modelsCacheKey, cached.chatCacheKey
		} else if firstModelsKey == cached.modelsCacheKey || firstChatKey == cached.chatCacheKey {
			t.Error("different endpoints share a cache identity")
		}
		cached.ai = &stubAI{chatErr: errors.New("unknown model")}
		if _, err := cached.Chat(); err == nil || cache.deleteModelsKey != cached.modelsCacheKey {
			t.Errorf("model error did not invalidate the endpoint catalog: %v", err)
		}
	}
	client, err := NewAI(context.Background(), &Config{Provider: "openai", Model: "test-model", TemperatureSet: true, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	if cached := client.(*CachingAI); cached.modelsCacheKey != firstModelsKey || cached.chatCacheKey == firstChatKey {
		t.Error("explicit sampling must change the chat cache identity only")
	}
	other, err := NewAI(context.Background(), &Config{Provider: "openai", Model: "test-model", Temperature: 0.8, TemperatureSet: true, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	if other.(*CachingAI).chatCacheKey == client.(*CachingAI).chatCacheKey {
		t.Error("an explicit zero must not reuse a nonzero sampling response")
	}
}

func TestCompatibleExplicitModelSkipsCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[{"message":{"content":"test response"}}]}`)
	}))
	defer server.Close()
	client, err := NewAI(context.Background(), &Config{Provider: "openai-compatible", BaseURL: server.URL + "/v1", APIKey: "test-key", Model: "unlisted-model", DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := client.Chat(); err != nil || got != "test response" {
		t.Fatalf("Chat() = %q, %v", got, err)
	}
}

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
	getChatKey      string
	setChatKey      string
	getModelsKey    string
	setModelsKey    string
	deleteModelsKey string
}

func (c *recordingCache) Get(_ string, provider string, _, _ string, _, _ float64) (*model.ChatResponse, error) {
	c.getChatKey = provider
	return nil, model.ErrNotFound
}

func (c *recordingCache) Set(chat *model.ChatResponse) error {
	c.setChatKey = chat.Provider
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
