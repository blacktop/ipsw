package disass

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ai"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
)

type Config struct {
	UUID         string
	LLM          string
	Language     string
	Model        string
	Temperature  float64
	TopP         float64
	Stream       bool
	DisableCache bool
	Verbose      bool
	Color        bool
	Theme        string
	MaxRetries   int
	RetryBackoff time.Duration
}

func Decompile(asm string, cfg *Config) (string, error) {
	promptFmt, lexer, err := disass.GetPrompt(asm, cfg.Language)
	if err != nil {
		return "", fmt.Errorf("failed to get prompt format string and syntax highlight lexer: %v", err)
	}
	llm, err := ai.NewAI(context.Background(), &ai.Config{
		UUID:         cfg.UUID,
		Provider:     cfg.LLM,
		Prompt:       fmt.Sprintf(promptFmt, asm),
		Model:        cfg.Model,
		Temperature:  cfg.Temperature,
		TopP:         cfg.TopP,
		Stream:       cfg.Stream,
		DisableCache: cfg.DisableCache,
		Verbose:      cfg.Verbose,
		MaxRetries:   cfg.MaxRetries,
		RetryBackoff: cfg.RetryBackoff,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create llm client: %v", err)
	}
	if cfg.Model == "" {
		modelMap, err := llm.Models()
		if err != nil {
			return "", fmt.Errorf("failed to get llm models: %v", err)
		}
		models := slices.Collect(maps.Keys(modelMap))
		sort.Strings(models)

		var choice string
		prompt := &survey.Select{
			Message:  "Select model to use:",
			Options:  models,
			PageSize: 10,
		}
		if err := survey.AskOne(prompt, &choice); err == terminal.InterruptErr {
			log.Warn("Exiting...")
			return "", nil
		}
		if err := llm.SetModel(choice); err != nil {
			return "", fmt.Errorf("failed to set llm model: %v", err)
		}
	}
	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond)
	s.Prefix = color.BlueString("   • Decompiling... ")
	s.Start()

	decmp, err := llm.Chat()
	s.Stop()
	if err != nil {
		return "", fmt.Errorf("failed to decompile via llm: %v", err)
	}
	if cfg.Color {
		var buf strings.Builder
		if err := quick.Highlight(&buf, "\n"+string(decmp)+"\n", lexer, "terminal256", cfg.Theme); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	return decmp, nil
}
