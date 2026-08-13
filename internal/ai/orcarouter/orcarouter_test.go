package orcarouter

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSupportsTextChat(t *testing.T) {
	tests := []struct {
		name  string
		model modelInfo
		want  bool
	}{
		{
			name: "openai text chat",
			model: newTestModel(
				[]string{"openai"},
				[]string{"text", "image"},
				[]string{"text"},
			),
			want: true,
		},
		{
			name: "translated anthropic text chat",
			model: newTestModel(
				[]string{"anthropic", "openai"},
				[]string{"text"},
				[]string{"text"},
			),
			want: true,
		},
		{
			name: "native only text",
			model: newTestModel(
				[]string{"anthropic"},
				[]string{"text"},
				[]string{"text"},
			),
		},
		{
			name: "missing model id",
			model: modelInfo{
				Object:                 "model",
				SupportedEndpointTypes: []string{"openai"},
				Architecture: modelArchitecture{
					InputModalities:  []string{"text"},
					OutputModalities: []string{"text"},
				},
			},
		},
		{
			name: "invalid object type",
			model: modelInfo{
				ID:                     "test/model",
				Object:                 "router",
				SupportedEndpointTypes: []string{"openai"},
				Architecture: modelArchitecture{
					InputModalities:  []string{"text"},
					OutputModalities: []string{"text"},
				},
			},
		},
		{
			name: "model id with surrounding whitespace",
			model: modelInfo{
				ID:                     " test/model ",
				Object:                 "model",
				SupportedEndpointTypes: []string{"openai"},
				Architecture: modelArchitecture{
					InputModalities:  []string{"text"},
					OutputModalities: []string{"text"},
				},
			},
		},
		{
			name: "text to speech",
			model: newTestModel(
				[]string{"openai"},
				[]string{"text"},
				[]string{"audio"},
			),
		},
		{
			name: "speech to text",
			model: newTestModel(
				[]string{"openai"},
				[]string{"audio"},
				[]string{"text"},
			),
		},
		{
			name: "video",
			model: newTestModel(
				[]string{"openai"},
				[]string{"text"},
				[]string{"video"},
			),
		},
		{
			name: "missing capability metadata",
			model: newTestModel(
				[]string{"openai"},
				nil,
				nil,
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := supportsTextChat(tt.model); got != tt.want {
				t.Fatalf("supportsTextChat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrcaRouterTextChatLifecycle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
			t.Errorf("Authorization = %q, want Bearer test-api-key", got)
		}

		switch r.URL.Path {
		case "/models":
			writeJSON(t, w, modelsResponse{Data: []modelInfo{
				{
					ID:                     "openai/gpt-5.5",
					Object:                 "model",
					SupportedEndpointTypes: []string{"openai"},
					Architecture: modelArchitecture{
						InputModalities:  []string{"text"},
						OutputModalities: []string{"text"},
					},
				},
				{
					ID:                     "openai/tts-1",
					Object:                 "model",
					SupportedEndpointTypes: []string{"openai"},
					Architecture: modelArchitecture{
						InputModalities:  []string{"text"},
						OutputModalities: []string{"audio"},
					},
				},
			}})
		case "/chat/completions":
			var request chatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode chat request: %v", err)
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			if request.Model != "openai/gpt-5.5" {
				t.Errorf("chat model = %q, want openai/gpt-5.5", request.Model)
			}
			if len(request.Messages) != 1 || request.Messages[0].Content != "decompile this" {
				t.Errorf("chat messages = %#v, want decompile prompt", request.Messages)
			}
			writeJSON(t, w, map[string]any{
				"choices": []map[string]any{
					{"message": map[string]string{"role": "assistant", "content": "decompiled"}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := newOrcaRouter(
		context.Background(),
		&Config{Prompt: "decompile this"},
		"test-api-key",
		server.URL,
		server.Client(),
	)
	if err != nil {
		t.Fatalf("NewOrcaRouter() error = %v", err)
	}

	models, err := client.Models()
	if err != nil {
		t.Fatalf("Models() error = %v", err)
	}
	wantModels := map[string]string{"openai/gpt-5.5": "openai/gpt-5.5"}
	if !maps.Equal(models, wantModels) {
		t.Fatalf("Models() = %#v, want %#v", models, wantModels)
	}
	if err := client.SetModel("openai/tts-1"); err == nil {
		t.Fatal("SetModel(openai/tts-1) error = nil, want unsupported model error")
	}
	if err := client.SetModel("openai/gpt-5.5"); err != nil {
		t.Fatalf("SetModel(openai/gpt-5.5) error = %v", err)
	}

	response, err := client.Chat()
	if err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if response != "decompiled" {
		t.Fatalf("Chat() = %q, want decompiled", response)
	}
}

func TestOrcaRouterRejectsEmptyTextChatCatalog(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, modelsResponse{Data: []modelInfo{
			{
				ID:                     "kling/kling-v3-omni",
				Object:                 "model",
				SupportedEndpointTypes: []string{"openai"},
				Architecture: modelArchitecture{
					InputModalities:  []string{"text"},
					OutputModalities: []string{"video"},
				},
			},
		}})
	}))
	defer server.Close()

	client, err := newOrcaRouter(
		context.Background(),
		&Config{},
		"test-api-key",
		server.URL,
		server.Client(),
	)
	if err != nil {
		t.Fatalf("NewOrcaRouter() error = %v", err)
	}
	if _, err := client.Models(); err == nil {
		t.Fatal("Models() error = nil, want empty text chat catalog error")
	}
}

func newTestModel(endpointTypes, inputModalities, outputModalities []string) modelInfo {
	return modelInfo{
		ID:                     "test/model",
		Object:                 "model",
		SupportedEndpointTypes: endpointTypes,
		Architecture: modelArchitecture{
			InputModalities:  inputModalities,
			OutputModalities: outputModalities,
		},
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode response: %v", err)
	}
}
