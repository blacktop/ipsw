package acp

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

	cwd, _, conn, err := newClientConnection(stdin, stdout)
	if err != nil {
		return nil, err
	}
	if err := initializeClient(ctx, conn); err != nil {
		return nil, err
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

	cwd string
}

var _ acp.Client = (*collectingClient)(nil)

func (c *collectingClient) RequestPermission(ctx context.Context, p acp.RequestPermissionRequest) (acp.RequestPermissionResponse, error) {
	if id, ok := autoApprovedPermissionOption(p); ok {
		return acp.RequestPermissionResponse{Outcome: acp.NewRequestPermissionOutcomeSelected(id)}, nil
	}
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

func (c *collectingClient) ReadTextFile(ctx context.Context, req acp.ReadTextFileRequest) (acp.ReadTextFileResponse, error) {
	if err := ctx.Err(); err != nil {
		return acp.ReadTextFileResponse{}, err
	}
	path, err := c.resolveReadPath(req.Path)
	if err != nil {
		return acp.ReadTextFileResponse{}, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return acp.ReadTextFileResponse{}, fmt.Errorf("acp client: read %s: %w", req.Path, err)
	}
	return acp.ReadTextFileResponse{Content: readTextWindow(string(b), req.Line, req.Limit)}, nil
}

func (c *collectingClient) WriteTextFile(ctx context.Context, _ acp.WriteTextFileRequest) (acp.WriteTextFileResponse, error) {
	return acp.WriteTextFileResponse{}, fmt.Errorf("acp client: writeTextFile denied")
}

func (c *collectingClient) CreateTerminal(ctx context.Context, _ acp.CreateTerminalRequest) (acp.CreateTerminalResponse, error) {
	return acp.CreateTerminalResponse{}, fmt.Errorf("acp client: terminal not supported")
}

func (c *collectingClient) KillTerminal(ctx context.Context, _ acp.KillTerminalRequest) (acp.KillTerminalResponse, error) {
	return acp.KillTerminalResponse{}, fmt.Errorf("acp client: terminal not supported")
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

func newClientConnection(stdin io.Writer, stdout io.Reader) (string, *collectingClient, *acp.ClientSideConnection, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", nil, nil, fmt.Errorf("acp: failed to get current working directory: %w", err)
	}
	client := &collectingClient{cwd: cwd}
	conn := acp.NewClientSideConnection(client, stdin, stdout)
	return cwd, client, conn, nil
}

func initializeClient(ctx context.Context, conn *acp.ClientSideConnection) error {
	_, err := conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientCapabilities: acp.ClientCapabilities{
			// NOTE: Some ACP agents (notably gemini --experimental-acp) validate that
			// fs.readTextFile and fs.writeTextFile are present in the initialize payload.
			// The SDK uses `omitempty` on these booleans, so `false` would be omitted and
			// the agent rejects the request. We support readTextFile within the
			// session cwd and keep writeTextFile denied in the handler implementation.
			Fs:       acp.FileSystemCapabilities{ReadTextFile: true, WriteTextFile: true},
			Terminal: false,
		},
	})
	if err != nil {
		return fmt.Errorf("acp: initialize failed: %w", err)
	}
	return nil
}

func autoApprovedPermissionOption(req acp.RequestPermissionRequest) (acp.PermissionOptionId, bool) {
	if req.ToolCall.Kind == nil {
		return "", false
	}
	switch *req.ToolCall.Kind {
	case acp.ToolKindRead, acp.ToolKindSearch, acp.ToolKindThink:
	default:
		return "", false
	}
	for _, opt := range req.Options {
		if opt.Kind == acp.PermissionOptionKindAllowOnce {
			return opt.OptionId, true
		}
	}
	for _, opt := range req.Options {
		if opt.Kind == acp.PermissionOptionKindAllowAlways {
			return opt.OptionId, true
		}
	}
	return "", false
}

func (c *collectingClient) resolveReadPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("acp client: readTextFile path must be absolute: %s", path)
	}
	root, err := filepath.Abs(c.cwd)
	if err != nil {
		return "", fmt.Errorf("acp client: resolve cwd %s: %w", c.cwd, err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("acp client: resolve cwd %s: %w", c.cwd, err)
	}
	target, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("acp client: resolve read path %s: %w", path, err)
	}
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return "", fmt.Errorf("acp client: resolve read path %s relative to %s: %w", path, root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("acp client: readTextFile outside session cwd denied: %s", path)
	}
	return target, nil
}

func readTextWindow(content string, line, limit *int) string {
	if line == nil && limit == nil {
		return content
	}
	lines := strings.Split(content, "\n")
	start := 0
	if line != nil && *line > 1 {
		start = *line - 1
		if start > len(lines) {
			start = len(lines)
		}
	}
	end := len(lines)
	if limit != nil {
		if *limit <= 0 {
			end = start
		} else if start+*limit < end {
			end = start + *limit
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func promptStopError(reason acp.StopReason, resp string) error {
	resp = strings.TrimSpace(utils.Clean(resp))
	if resp == "" {
		return fmt.Errorf("acp: prompt stopped with %s", reason)
	}
	const maxStopReasonSnippet = 1024
	if len(resp) > maxStopReasonSnippet {
		resp = resp[:maxStopReasonSnippet] + "... (truncated)"
	}
	return fmt.Errorf("acp: prompt stopped with %s: %s", reason, resp)
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

	cwd, client, conn, err := newClientConnection(stdin, stdout)
	if err != nil {
		return "", err
	}
	if err := initializeClient(ctx, conn); err != nil {
		return "", err
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
		if _, setErr := conn.UnstableSetSessionModel(ctx, acp.UnstableSetSessionModelRequest{SessionId: sess.SessionId, ModelId: acp.UnstableModelId(m)}); setErr != nil {
			if c.conf.Verbose {
				log.Debugf("acp: UnstableSetSessionModel failed (ignored): %v", setErr)
			}
		}
	}

	promptResp, err := conn.Prompt(ctx, acp.PromptRequest{
		SessionId: sess.SessionId,
		Prompt:    []acp.ContentBlock{acp.TextBlock(c.conf.Prompt)},
	})
	if err != nil {
		return "", fmt.Errorf("acp: prompt failed: %w", err)
	}

	resp := strings.TrimSpace(client.String())
	if promptResp.StopReason != "" && promptResp.StopReason != acp.StopReasonEndTurn {
		return "", promptStopError(promptResp.StopReason, resp)
	}
	if resp == "" {
		return "", fmt.Errorf("no content returned from agent")
	}

	return utils.Clean(resp), nil
}

func (c *ACP) Close() error {
	return nil
}
