package disass

import (
	"context"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/ai"
	"github.com/blacktop/ipsw/internal/colors"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/briandowns/spinner"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type Config struct {
	UUID           string
	LLM            string
	Language       string
	Model          string
	Temperature    float64
	TopP           float64
	TemperatureSet bool
	TopPSet        bool
	Stream         bool
	DisableCache   bool
	Verbose        bool
	Color          bool
	Theme          string
	MaxRetries     int
	RetryBackoff   time.Duration
}

func Decompile(asm string, cfg *Config) (string, error) {
	promptFmt, lexer, err := disass.GetPrompt(asm, cfg.Language)
	if err != nil {
		return "", fmt.Errorf("failed to get prompt format string and syntax highlight lexer: %v", err)
	}
	llm, err := ai.NewAI(context.Background(), &ai.Config{
		UUID:           cfg.UUID,
		Provider:       cfg.LLM,
		Prompt:         fmt.Sprintf(promptFmt, asm),
		Model:          cfg.Model,
		Temperature:    cfg.Temperature,
		TemperatureSet: cfg.TemperatureSet,
		TopP:           cfg.TopP,
		TopPSet:        cfg.TopPSet,
		Stream:         cfg.Stream,
		DisableCache:   cfg.DisableCache,
		Verbose:        cfg.Verbose,
		MaxRetries:     cfg.MaxRetries,
		RetryBackoff:   cfg.RetryBackoff,
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

		// If the provider only offers a single 'default' model, don't bother prompting.
		if len(models) == 1 {
			choice := models[0]
			modelID := modelMap[choice]
			if modelID == "" {
				modelID = choice
			}
			if choice == "default" || modelID == "default" {
				if err := llm.SetModel("default"); err != nil {
					return "", fmt.Errorf("failed to set llm model: %v", err)
				}
				goto decompile
			}
		}

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

decompile:
	s := spinner.New(spinner.CharSets[38], 100*time.Millisecond)
	s.Prefix = colors.Blue().Sprint("   • Decompiling... ")
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

// FlagWasProvided reports whether a CLI flag was explicitly set via the command line
// or supplied through a config file. This allows callers to distinguish user intent
// from default values when forwarding options to downstream systems.
func FlagWasProvided(cmd *cobra.Command, flagName, viperKey string) bool {
	if cmd.Flags().Changed(flagName) {
		return true
	}
	if viper.InConfig(viperKey) {
		return true
	}
	flag := cmd.Flags().Lookup(flagName)
	if flag == nil {
		return false
	}
	defVal, err := strconv.ParseFloat(flag.DefValue, 64)
	if err != nil {
		return false
	}
	current := viper.GetFloat64(viperKey)
	return math.Abs(current-defVal) > 1e-9
}
