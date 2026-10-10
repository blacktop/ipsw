package openai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestModelCatalogCapabilities(t *testing.T) {
	for _, tt := range []struct {
		name   string
		fields string
		want   bool
	}{
		{"plain model", ``, true},
		{"text", `,"type":"text"`, true},
		{"image", `,"type":"image"`, false},
		{"video", `,"type":"video"`, false},
		{"embedding", `,"type":"embedding"`, false},
		{"chat endpoint", `,"endpoint":"/v1/chat/completions"`, true},
		{"responses only", `,"type":"text","supported_endpoints":["/v1/responses"]`, false},
		{"preferred responses", `,"endpoint":"/v1/responses","supported_endpoints":["/v1/responses","/v1/chat/completions"]`, true},
		{"restricted chat", `,"endpoint":"/v1/chat/completions","supported_endpoints":["/v1/responses"]`, false},
		{"empty endpoints", `,"supported_endpoints":[]`, false},
		{"native only", `,"supported_endpoint_types":["anthropic"]`, false},
		{"text output", `,"architecture":{"input_modalities":["text","image"],"output_modalities":["text"]}`, true},
		{"audio output", `,"architecture":{"output_modalities":["audio"]}`, false},
		{"empty output", `,"architecture":{"output_modalities":[]}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var model modelInfo
			if err := json.Unmarshal([]byte(`{"id":"test-model","object":"model"`+tt.fields+`}`), &model); err != nil {
				t.Fatal(err)
			}
			if got := model.canListForTextChat(); got != tt.want {
				t.Fatalf("canListForTextChat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompatibleEndpointModelsAndChat(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "unused-default-key")
	t.Setenv("TEST_COMPATIBLE_API_KEY", "test-gateway-key")
	t.Setenv("OPENAI_ORG_ID", "unused-organization")
	t.Setenv("OPENAI_PROJECT_ID", "unused-project")
	var requests []string
	var requestsMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsMu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		requestIndex := len(requests)
		requestsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if got := r.Header.Get("Authorization"); got != "Bearer test-gateway-key" {
			t.Errorf("Authorization = %q", got)
		}
		if r.Header.Get("OpenAI-Organization") != "" || r.Header.Get("OpenAI-Project") != "" {
			t.Error("OpenAI account headers were forwarded to a compatible endpoint")
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /gateway/v1/models":
			fmt.Fprint(w, `{"data":[{"id":"test-chat","object":"model","type":"text","supported_endpoints":["/v1/chat/completions"]},{"id":"test-image","type":"image"},{"id":"test-pro","type":"text","supported_endpoints":["/v1/responses"]},{"id":"test-plain"}]}`)
		case "POST /gateway/v1/chat/completions":
			var body struct {
				Model       string                           `json:"model"`
				Messages    []struct{ Role, Content string } `json:"messages"`
				Temperature *float64                         `json:"temperature"`
				TopP        *float64                         `json:"top_p"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Model != "test-private-model" || len(body.Messages) != 1 || body.Messages[0].Content != "test prompt" || body.Messages[0].Role != "user" {
				t.Errorf("unexpected chat request: %+v", body)
			}
			if requestIndex == 2 {
				if body.Temperature == nil || *body.Temperature != 0 || body.TopP == nil || *body.TopP != 0.7 {
					t.Errorf("explicit sampling controls missing: %+v", body)
				}
			} else if body.Temperature != nil || body.TopP != nil {
				t.Error("unset sampling controls were sent")
			}
			fmt.Fprint(w, "{\"choices\":[{\"message\":{\"content\":\"```c\\nint synthetic(void) { return 7; }\\n```\"}}]}")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("OPENAI_BASE_URL", server.URL+"/unused")
	conf := &Config{BaseURL: server.URL + "/gateway/v1/", APIKeyEnv: "TEST_COMPATIBLE_API_KEY", Prompt: "test prompt", Model: "test-private-model"}
	client, err := NewOpenAI(context.Background(), conf)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if i == 1 {
			conf.TemperatureSet, conf.TopPSet, conf.TopP = true, true, 0.7
		}
		got, err := client.Chat()
		if err != nil || got != "int synthetic(void) { return 7; }" {
			t.Fatalf("Chat() = %q, %v", got, err)
		}
	}
	requestsMu.Lock()
	gotRequests := append([]string(nil), requests...)
	requestsMu.Unlock()
	if !reflect.DeepEqual(gotRequests, []string{"POST /gateway/v1/chat/completions", "POST /gateway/v1/chat/completions"}) {
		t.Fatalf("explicit model unexpectedly fetched catalog: %v", gotRequests)
	}
	models, err := client.Models()
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"test-chat": "test-chat", "test-plain": "test-plain"}; !reflect.DeepEqual(models, want) {
		t.Fatalf("Models() = %v, want %v", models, want)
	}
	if err := client.SetModel("unlisted-model"); err != nil {
		t.Fatalf("SetModel() should accept an explicit ID: %v", err)
	}
}

func TestEndpointConfigurationAndCacheIdentity(t *testing.T) {
	t.Setenv("OPENAI_BASE_URL", "https://gateway.example/v1/")
	t.Setenv("OPENAI_API_KEY", "test-default-key")
	t.Setenv("TEST_MISSING_API_KEY", "")
	newClient := func(conf *Config) *OpenAI {
		t.Helper()
		client, err := NewOpenAI(context.Background(), conf)
		if err != nil {
			t.Fatal(err)
		}
		return client
	}
	fromEnv := newClient(&Config{}).CacheKey()
	if explicit := newClient(&Config{BaseURL: "https://gateway.example/v1", APIKey: "test-default-key"}).CacheKey(); explicit != fromEnv {
		t.Error("equivalent environment and explicit config have different cache identities")
	}
	for _, conf := range []*Config{
		{BaseURL: "https://another.example/v1"},
		{BaseURL: "https://gateway.example/other/v1"},
		{APIKey: "test-other-key"},
	} {
		if got := newClient(conf).CacheKey(); got == fromEnv || strings.Contains(got, "test-") || strings.Contains(got, "gateway.example") {
			t.Errorf("cache identity did not isolate or conceal configuration: %q", got)
		}
	}
	if _, err := NewOpenAI(context.Background(), &Config{APIKeyEnv: "TEST_MISSING_API_KEY"}); err == nil {
		t.Error("missing explicitly named key silently fell back to OPENAI_API_KEY")
	}
	for _, baseURL := range []string{"/relative/v1", "file:///tmp/models", "https://user:secret@example.com/v1", "https://example.com/v1?key=secret", "https://example.com/v1#secret"} {
		if _, err := NewOpenAI(context.Background(), &Config{BaseURL: baseURL}); err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("invalid URL was accepted or exposed: %v", err)
		}
	}
}

func TestUnauthenticatedEndpointAndEmptyResponse(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("empty API key produced an Authorization header")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"choices":[]}`)
	}))
	defer server.Close()
	client, err := NewOpenAI(context.Background(), &Config{BaseURL: server.URL + "/v1", Model: "test-model"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Chat(); err == nil || !strings.Contains(err.Error(), "no content") {
		t.Fatalf("Chat() error = %v, want empty-response error", err)
	}
}
