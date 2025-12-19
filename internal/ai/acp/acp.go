package acp

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	acp "github.com/coder/acp-go-sdk"

	"github.com/blacktop/ipsw/internal/ai/utils"
)

type Config struct {
	Prompt      string  `json:"prompt"`
	Model       string  `json:"model"`
	Temperature float64 `json:"temperature"`
	TopP        float64 `json:"top_p"`
	Stream      bool    `json:"stream"`

	Command string   `json:"-"`
	Args    []string `json:"-"`
	Env     []string `json:"-"`
	Verbose bool     `json:"-"`
}

type ACP struct {
	ctx    context.Context
	conf   *Config
	models map[string]string
}

func New(ctx context.Context, conf *Config) (*ACP, error) {
	if conf == nil {
		return nil, fmt.Errorf("acp: config is nil")
	}
	if strings.TrimSpace(conf.Command) == "" {
		return nil, fmt.Errorf("acp: command is required")
	}
	return &ACP{ctx: ctx, conf: conf}, nil
}

func (c *ACP) Models() (map[string]string, error) {
	if len(c.models) > 0 {
		return c.models, nil
	}

	// If the user pre-selected a model, treat it as the only selectable option.
	if strings.TrimSpace(c.conf.Model) != "" {
		c.models = map[string]string{c.conf.Model: c.conf.Model}
		return c.models, nil
	}

	// Attempt to query supported models via ACP. The protocol exposes this via the
	// (unstable) SessionModelState returned from `session/new`.
	models, err := c.fetchModelsViaACP()
	if err == nil && len(models) > 0 {
		c.models = models
		return c.models, nil
	}
	if err != nil && c.conf.Verbose {
		log.Debugf("acp: failed to fetch models (falling back to default): %v", err)
	}

	// Fallback: the rest of the codebase expects at least one selectable model.
	c.models = map[string]string{"default": "default"}
	return c.models, nil
}

func (c *ACP) fetchModelsViaACP() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.conf.Command, c.conf.Args...)
	cmd.Env = append(os.Environ(), c.conf.Env...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("acp: failed to get stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("acp: failed to get stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("acp: failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("acp: failed to start agent command '%s': %w", c.conf.Command, err)
	}
	defer func() {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	go func() {
		if c.conf.Verbose {
			_, _ = io.Copy(os.Stderr, stderr)
		} else {
			_, _ = io.Copy(io.Discard, stderr)
		}
	}()

	client := &collectingClient{}
	conn := acp.NewClientSideConnection(client, stdin, stdout)

	if _, err = conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientCapabilities: acp.ClientCapabilities{
			// NOTE: Some ACP agents (notably gemini --experimental-acp) validate that
			// fs.readTextFile and fs.writeTextFile are present in the initialize payload.
			// The SDK uses `omitempty` on these booleans, so `false` would be omitted and
			// the agent rejects the request. We advertise support but still enforce a
			// deny-by-default policy in the handler implementations.
			Fs:       acp.FileSystemCapability{ReadTextFile: true, WriteTextFile: true},
			Terminal: false,
		},
	}); err != nil {
		return nil, fmt.Errorf("acp: initialize failed: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "/"
	}

	sess, err := conn.NewSession(ctx, acp.NewSessionRequest{
		Cwd:        cwd,
		McpServers: []acp.McpServer{},
	})
	if err != nil {
		return nil, fmt.Errorf("acp: newSession failed: %w", err)
	}

	models := make(map[string]string)
	if sess.Models == nil {
		return models, nil
	}
	for _, mi := range sess.Models.AvailableModels {
		id := strings.TrimSpace(string(mi.ModelId))
		if id == "" {
			continue
		}
		key := strings.TrimSpace(mi.Name)
		if key == "" {
			key = id
		}
		if _, exists := models[key]; exists {
			key = fmt.Sprintf("%s (%s)", key, id)
		}
		models[key] = id
	}

	return models, nil
}

func (c *ACP) SetModel(model string) error {
	model = strings.TrimSpace(model)
	if model == "" {
		return fmt.Errorf("no model specified")
	}
	if c.models == nil {
		c.models = make(map[string]string)
	}
	// ACP agents/adapters may accept arbitrary model IDs without a prior list.
	if _, ok := c.models[model]; !ok {
		c.models[model] = model
	}
	c.conf.Model = model
	return nil
}

func (c *ACP) SetModels(models map[string]string) (map[string]string, error) {
	c.models = models
	return c.models, nil
}

func (c *ACP) Verify() error {
	if strings.TrimSpace(c.conf.Model) == "" {
		return fmt.Errorf("no model specified")
	}
	if c.models == nil {
		c.models = make(map[string]string)
	}
	if _, ok := c.models[c.conf.Model]; !ok {
		c.models[c.conf.Model] = c.conf.Model
	}
	if c.models[c.conf.Model] == "" {
		return fmt.Errorf("model '%s' has empty ID", c.conf.Model)
	}
	return nil
}

type collectingClient struct {
	mu sync.Mutex
	b  strings.Builder
}

var _ acp.Client = (*collectingClient)(nil)

func (c *collectingClient) RequestPermission(ctx context.Context, p acp.RequestPermissionRequest) (acp.RequestPermissionResponse, error) {
	// Default to cancelling any tool permissions. The decompiler prompt should not require tools.
	return acp.RequestPermissionResponse{Outcome: acp.RequestPermissionOutcome{Cancelled: &acp.RequestPermissionOutcomeCancelled{}}}, nil
}

func (c *collectingClient) SessionUpdate(ctx context.Context, n acp.SessionNotification) error {
	if n.Update.AgentMessageChunk != nil {
		content := n.Update.AgentMessageChunk.Content
		if content.Text != nil {
			c.mu.Lock()
			c.b.WriteString(content.Text.Text)
			c.mu.Unlock()
		}
	}
	return nil
}

func (c *collectingClient) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.b.String()
}

func (c *collectingClient) ReadTextFile(ctx context.Context, _ acp.ReadTextFileRequest) (acp.ReadTextFileResponse, error) {
	return acp.ReadTextFileResponse{}, fmt.Errorf("acp client: readTextFile denied")
}

func (c *collectingClient) WriteTextFile(ctx context.Context, _ acp.WriteTextFileRequest) (acp.WriteTextFileResponse, error) {
	return acp.WriteTextFileResponse{}, fmt.Errorf("acp client: writeTextFile denied")
}

func (c *collectingClient) CreateTerminal(ctx context.Context, _ acp.CreateTerminalRequest) (acp.CreateTerminalResponse, error) {
	return acp.CreateTerminalResponse{}, fmt.Errorf("acp client: terminal not supported")
}

func (c *collectingClient) KillTerminalCommand(ctx context.Context, _ acp.KillTerminalCommandRequest) (acp.KillTerminalCommandResponse, error) {
	return acp.KillTerminalCommandResponse{}, fmt.Errorf("acp client: terminal not supported")
}

func (c *collectingClient) ReleaseTerminal(ctx context.Context, _ acp.ReleaseTerminalRequest) (acp.ReleaseTerminalResponse, error) {
	return acp.ReleaseTerminalResponse{}, fmt.Errorf("acp client: terminal not supported")
}

func (c *collectingClient) TerminalOutput(ctx context.Context, _ acp.TerminalOutputRequest) (acp.TerminalOutputResponse, error) {
	return acp.TerminalOutputResponse{}, fmt.Errorf("acp client: terminal not supported")
}

func (c *collectingClient) WaitForTerminalExit(ctx context.Context, _ acp.WaitForTerminalExitRequest) (acp.WaitForTerminalExitResponse, error) {
	return acp.WaitForTerminalExitResponse{}, fmt.Errorf("acp client: terminal not supported")
}

func (c *ACP) Chat() (string, error) {
	if err := c.Verify(); err != nil {
		return "", fmt.Errorf("invalid model configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.conf.Command, c.conf.Args...)
	cmd.Env = append(os.Environ(), c.conf.Env...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("acp: failed to get stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("acp: failed to get stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("acp: failed to get stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("acp: failed to start agent command '%s': %w", c.conf.Command, err)
	}
	defer func() {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	go func() {
		if c.conf.Verbose {
			_, _ = io.Copy(os.Stderr, stderr)
		} else {
			_, _ = io.Copy(io.Discard, stderr)
		}
	}()

	client := &collectingClient{}
	conn := acp.NewClientSideConnection(client, stdin, stdout)

	if _, err = conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientCapabilities: acp.ClientCapabilities{
			// NOTE: Some ACP agents (notably gemini --experimental-acp) validate that
			// fs.readTextFile and fs.writeTextFile are present in the initialize payload.
			// The SDK uses `omitempty` on these booleans, so `false` would be omitted and
			// the agent rejects the request. We advertise support but still enforce a
			// deny-by-default policy in the handler implementations.
			Fs:       acp.FileSystemCapability{ReadTextFile: true, WriteTextFile: true},
			Terminal: false,
		},
	}); err != nil {
		return "", fmt.Errorf("acp: initialize failed: %w", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "/"
	}

	sess, err := conn.NewSession(ctx, acp.NewSessionRequest{
		Cwd:        cwd,
		McpServers: []acp.McpServer{},
	})
	if err != nil {
		return "", fmt.Errorf("acp: newSession failed: %w", err)
	}

	// Best-effort: attempt to set model if the agent supports it (UNSTABLE ACP API).
	if m := strings.TrimSpace(c.conf.Model); m != "" && m != "default" {
		if _, setErr := conn.SetSessionModel(ctx, acp.SetSessionModelRequest{SessionId: sess.SessionId, ModelId: acp.ModelId(m)}); setErr != nil {
			if c.conf.Verbose {
				log.Debugf("acp: SetSessionModel failed (ignored): %v", setErr)
			}
		}
	}

	if _, err = conn.Prompt(ctx, acp.PromptRequest{
		SessionId: sess.SessionId,
		Prompt:    []acp.ContentBlock{acp.TextBlock(c.conf.Prompt)},
	}); err != nil {
		return "", fmt.Errorf("acp: prompt failed: %w", err)
	}

	resp := strings.TrimSpace(client.String())
	if resp == "" {
		return "", fmt.Errorf("no content returned from agent")
	}

	return utils.Clean(resp), nil
}

func (c *ACP) Close() error {
	return nil
}
