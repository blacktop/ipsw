package acp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acpsdk "github.com/coder/acp-go-sdk"
)

const (
	testACPAgentModeEnv = "IPSW_TEST_ACP_AGENT_MODE"
	testACPReadPathEnv  = "IPSW_TEST_ACP_READ_PATH"
)

func TestACPModelsFromAgent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := New(ctx, &Config{
		Prompt:  "decompile this",
		Command: os.Args[0],
		Args:    []string{"-test.run=TestACPAgentHelperProcess"},
		Env:     []string{testACPAgentModeEnv + "=ok"},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	models, err := client.Models()
	if err != nil {
		t.Fatalf("Models() error = %v", err)
	}
	if got := models["Test Model"]; got != "test-model" {
		t.Fatalf("Models()[Test Model] = %q, want test-model", got)
	}
}

func TestACPChatAllowsReadOnlyFileContext(t *testing.T) {
	dir := t.TempDir()
	readPath := filepath.Join(dir, "context.txt")
	if err := os.WriteFile(readPath, []byte("alpha\nbravo\ncharlie\n"), 0o644); err != nil {
		t.Fatalf("write test context: %v", err)
	}
	chdir(t, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newTestACP(t, ctx, "read", readPath)
	resp, err := client.Chat()
	if err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if resp != "read:bravo" {
		t.Fatalf("Chat() = %q, want read:bravo", resp)
	}
}

func TestACPChatReportsNonEndTurnStopReason(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := newTestACP(t, ctx, "cancelled", "")
	_, err := client.Chat()
	if err == nil {
		t.Fatal("Chat() error = nil, want stop reason error")
	}
	if !strings.Contains(err.Error(), "prompt stopped with cancelled") {
		t.Fatalf("Chat() error = %q, want cancelled stop reason", err)
	}
}

func TestCollectingClientReadTextFileRestrictsCWD(t *testing.T) {
	dir := t.TempDir()
	inside := filepath.Join(dir, "inside.txt")
	if err := os.WriteFile(inside, []byte("one\ntwo\nthree"), 0o644); err != nil {
		t.Fatalf("write inside file: %v", err)
	}
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	client := &collectingClient{cwd: dir}
	line, limit := 2, 1
	resp, err := client.ReadTextFile(context.Background(), acpsdk.ReadTextFileRequest{
		Path:  inside,
		Line:  &line,
		Limit: &limit,
	})
	if err != nil {
		t.Fatalf("ReadTextFile(inside) error = %v", err)
	}
	if resp.Content != "two" {
		t.Fatalf("ReadTextFile(inside) = %q, want two", resp.Content)
	}

	if _, err := client.ReadTextFile(context.Background(), acpsdk.ReadTextFileRequest{Path: outside}); err == nil {
		t.Fatal("ReadTextFile(outside) error = nil, want denial")
	}
}

func TestCollectingClientPermissionPolicy(t *testing.T) {
	client := &collectingClient{}
	tests := []struct {
		name      string
		kind      acpsdk.ToolKind
		wantAllow bool
	}{
		{name: "read", kind: acpsdk.ToolKindRead, wantAllow: true},
		{name: "edit", kind: acpsdk.ToolKindEdit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind := tt.kind
			resp, err := client.RequestPermission(context.Background(), acpsdk.RequestPermissionRequest{
				ToolCall: acpsdk.ToolCallUpdate{ToolCallId: acpsdk.ToolCallId(tt.name), Kind: &kind},
				Options: []acpsdk.PermissionOption{
					{Kind: acpsdk.PermissionOptionKindAllowOnce, Name: "Allow", OptionId: acpsdk.PermissionOptionId("allow")},
					{Kind: acpsdk.PermissionOptionKindRejectOnce, Name: "Reject", OptionId: acpsdk.PermissionOptionId("reject")},
				},
			})
			if err != nil {
				t.Fatalf("RequestPermission(%s) error = %v", tt.name, err)
			}
			if tt.wantAllow {
				if resp.Outcome.Selected == nil || resp.Outcome.Selected.OptionId != acpsdk.PermissionOptionId("allow") {
					t.Fatalf("RequestPermission(%s) = %#v, want allow selection", tt.name, resp.Outcome)
				}
				return
			}
			if resp.Outcome.Cancelled == nil {
				t.Fatalf("RequestPermission(%s) = %#v, want cancelled", tt.name, resp.Outcome)
			}
		})
	}
}

func newTestACP(t *testing.T, ctx context.Context, mode, readPath string) *ACP {
	t.Helper()
	client, err := New(ctx, &Config{
		Prompt:  "decompile this",
		Model:   "default",
		Command: os.Args[0],
		Args:    []string{"-test.run=TestACPAgentHelperProcess"},
		Env: []string{
			testACPAgentModeEnv + "=" + mode,
			testACPReadPathEnv + "=" + readPath,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Fatalf("restore cwd %s: %v", old, err)
		}
	})
}

func TestACPAgentHelperProcess(t *testing.T) {
	mode := os.Getenv(testACPAgentModeEnv)
	if mode == "" {
		return
	}

	agent := &testACPAgent{
		mode:     mode,
		readPath: os.Getenv(testACPReadPathEnv),
	}
	conn := acpsdk.NewAgentSideConnection(agent, os.Stdout, os.Stdin)
	agent.conn = conn
	<-conn.Done()
	os.Exit(0)
}

type testACPAgent struct {
	conn     *acpsdk.AgentSideConnection
	mode     string
	readPath string
}

var _ acpsdk.Agent = (*testACPAgent)(nil)

func (a *testACPAgent) Authenticate(ctx context.Context, _ acpsdk.AuthenticateRequest) (acpsdk.AuthenticateResponse, error) {
	return acpsdk.AuthenticateResponse{}, nil
}

func (a *testACPAgent) Initialize(ctx context.Context, _ acpsdk.InitializeRequest) (acpsdk.InitializeResponse, error) {
	return acpsdk.InitializeResponse{
		ProtocolVersion:   acpsdk.ProtocolVersionNumber,
		AgentCapabilities: acpsdk.AgentCapabilities{LoadSession: false},
	}, nil
}

func (a *testACPAgent) Cancel(ctx context.Context, _ acpsdk.CancelNotification) error {
	return nil
}

func (a *testACPAgent) CloseSession(ctx context.Context, _ acpsdk.CloseSessionRequest) (acpsdk.CloseSessionResponse, error) {
	return acpsdk.CloseSessionResponse{}, nil
}

func (a *testACPAgent) ListSessions(ctx context.Context, _ acpsdk.ListSessionsRequest) (acpsdk.ListSessionsResponse, error) {
	return acpsdk.ListSessionsResponse{}, nil
}

func (a *testACPAgent) NewSession(ctx context.Context, _ acpsdk.NewSessionRequest) (acpsdk.NewSessionResponse, error) {
	return acpsdk.NewSessionResponse{
		SessionId: acpsdk.SessionId("test-session"),
		Models: &acpsdk.SessionModelState{
			CurrentModelId: acpsdk.ModelId("test-model"),
			AvailableModels: []acpsdk.ModelInfo{{
				Name:    "Test Model",
				ModelId: acpsdk.ModelId("test-model"),
			}},
		},
	}, nil
}

func (a *testACPAgent) Prompt(ctx context.Context, req acpsdk.PromptRequest) (acpsdk.PromptResponse, error) {
	switch a.mode {
	case "cancelled":
		if err := a.sendText(ctx, req.SessionId, "partial output"); err != nil {
			return acpsdk.PromptResponse{}, err
		}
		return acpsdk.PromptResponse{StopReason: acpsdk.StopReasonCancelled}, nil
	case "read":
		kind := acpsdk.ToolKindRead
		perm, err := a.conn.RequestPermission(ctx, acpsdk.RequestPermissionRequest{
			SessionId: req.SessionId,
			ToolCall: acpsdk.ToolCallUpdate{
				ToolCallId: acpsdk.ToolCallId("read-context"),
				Kind:       &kind,
			},
			Options: []acpsdk.PermissionOption{
				{Kind: acpsdk.PermissionOptionKindAllowOnce, Name: "Allow", OptionId: acpsdk.PermissionOptionId("allow")},
				{Kind: acpsdk.PermissionOptionKindRejectOnce, Name: "Reject", OptionId: acpsdk.PermissionOptionId("reject")},
			},
		})
		if err != nil {
			return acpsdk.PromptResponse{}, err
		}
		if perm.Outcome.Selected == nil {
			return acpsdk.PromptResponse{}, fmt.Errorf("read permission was not selected")
		}
		line, limit := 2, 1
		file, err := a.conn.ReadTextFile(ctx, acpsdk.ReadTextFileRequest{
			SessionId: req.SessionId,
			Path:      a.readPath,
			Line:      &line,
			Limit:     &limit,
		})
		if err != nil {
			return acpsdk.PromptResponse{}, err
		}
		if err := a.sendText(ctx, req.SessionId, "read:"+file.Content); err != nil {
			return acpsdk.PromptResponse{}, err
		}
		return acpsdk.PromptResponse{StopReason: acpsdk.StopReasonEndTurn}, nil
	default:
		if err := a.sendText(ctx, req.SessionId, "ok"); err != nil {
			return acpsdk.PromptResponse{}, err
		}
		return acpsdk.PromptResponse{StopReason: acpsdk.StopReasonEndTurn}, nil
	}
}

func (a *testACPAgent) ResumeSession(ctx context.Context, _ acpsdk.ResumeSessionRequest) (acpsdk.ResumeSessionResponse, error) {
	return acpsdk.ResumeSessionResponse{}, nil
}

func (a *testACPAgent) SetSessionConfigOption(ctx context.Context, _ acpsdk.SetSessionConfigOptionRequest) (acpsdk.SetSessionConfigOptionResponse, error) {
	return acpsdk.SetSessionConfigOptionResponse{}, nil
}

func (a *testACPAgent) SetSessionMode(ctx context.Context, _ acpsdk.SetSessionModeRequest) (acpsdk.SetSessionModeResponse, error) {
	return acpsdk.SetSessionModeResponse{}, nil
}

func (a *testACPAgent) sendText(ctx context.Context, sessionID acpsdk.SessionId, text string) error {
	return a.conn.SessionUpdate(ctx, acpsdk.SessionNotification{
		SessionId: sessionID,
		Update:    acpsdk.UpdateAgentMessageText(text),
	})
}
