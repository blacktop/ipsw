---
hide_table_of_contents: true
description: Using the AI decompiler.
---

# AI Decompiler

> Transform assembly code into human-readable C/C++/ObjC/Swift code using AI models

The **ipsw AI decompiler** revolutionizes binary analysis by leveraging state-of-the-art language models to convert disassembly into readable, high-level code. Whether you're analyzing iOS binaries, kernelcache files, or dyld_shared_cache libraries, the AI decompiler provides intelligent code reconstruction.

## Requirements

There are currently 6 supported LLM providers

- Github Copilot
- OpenAI
- Claude (Anthropic)
- Gemini (Google AI)
- Ollama (local LLMs)
- OpenRouter (API access to multiple models)

## 🚀 Quick Start

```bash
# Decompile a binary's entry point with AI
ipsw macho disass /path/to/binary --entry --dec --dec-model "Claude 3.5 Sonnet"

# Analyze a specific function with context
ipsw macho disass /path/to/binary --symbol "_main" --dec --dec-llm "openai"

# Decompile dyld_shared_cache function as Swift
ipsw dsc disass dyld_shared_cache --vaddr 0x123456 --dec --dec-lang "Swift"
```

## 🔧 Provider Setup

### GitHub Copilot ⭐ *Recommended*

**Why Copilot?** Best value with access to premium models (GPT-4, Claude 3.5), plus you can use it in your IDE.

1. **Sign up**: https://github.com/features/copilot
2. **Enable models**: Go to https://github.com/settings/copilot and enable all available models
3. **Authenticate via one of these methods**:

   **Option A: Zed Editor** *(Easiest)*
   ```bash
   # Install Zed: https://zed.dev
   # Open Zed → Agent Panel (Cmd+?) → Settings (Opt+Cmd+C) → Sign in to GitHub Copilot Chat
   ```

   **Option B: Xcode**
   ```bash
   # Follow GitHub's Xcode setup guide
   # https://docs.github.com/en/copilot/managing-copilot/configure-personal-settings/installing-the-github-copilot-extension-in-your-environment?tool=xcode
   ```

4. **Verify setup**: Check that `~/.config/github-copilot/` contains `apps.json` or `hosts.json`

:::tip Free Models Available
GitHub Copilot offers FREE access to many premium models! See the [full list here](https://docs.github.com/en/copilot/about-github-copilot/plans-for-github-copilot#models).
:::

### OpenAI

```bash
# 1. Get API key from https://platform.openai.com/api-keys
# 2. Add to environment
export OPENAI_API_KEY="sk-your-key-here"

# 3. Use with ipsw
ipsw macho disass binary --dec --dec-llm openai
```

### Claude (Anthropic)

```bash
# 1. Get API key from https://console.anthropic.com/
# 2. Add to environment  
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# 3. Use with ipsw
ipsw macho disass binary --dec --dec-llm claude
```

### Gemini (Google AI)

```bash
# 1. Get API key from https://aistudio.google.com/apikey
# 2. Add to environment
export GEMINI_API_KEY="your-key-here"

# 3. Use with ipsw
ipsw macho disass binary --dec --dec-llm gemini
```

### Ollama (Local LLMs)

```bash
# 1. Install Ollama: https://ollama.com
# 2. Download models
ollama pull qwen2.5:32b-instruct  # Good for code analysis
ollama pull codellama:34b         # Code-specialized model

# 3. Start server and use
ollama serve
ipsw macho disass binary --dec --dec-llm ollama --dec-model "qwen2.5:32b-instruct"
```

:::warning Performance Note
Local LLMs require significant computational resources. Smaller models (7B-13B) may produce lower quality results compared to cloud-based models.
:::

### OpenRouter (Multi-Provider Access)

```bash
# 1. Get API key from https://openrouter.ai/
# 2. Set environment variables
export OPENROUTER_API_KEY="sk-or-your-key-here"
export OPENROUTER_CLIENT_TITLE="ipsw-decompiler"  # Optional: for usage tracking

# 3. Use with ipsw
ipsw macho disass binary --dec --dec-llm openrouter
```

## 📖 Usage Examples

There are 2 `ipsw` disassemblers:

- `ipsw macho disass` *(for single MachOs, including file-entries in the NEW kernelcaches)*
- `ipsw dsc disass` *(for dylibs in the dyld_shared_cache)*

### Binary Analysis

```bash
# Analyze iOS app main function
ipsw macho disass /Applications/MyApp.app/MyApp --symbol "_main" --dec

# Decompile with specific model
ipsw macho disass binary --entry --dec --dec-model "GPT-4" --dec-llm "openai"

# Force language interpretation
ipsw macho disass ObjCBinary --symbol "initWithFrame:" --dec --dec-lang "Objective-C"
```

### Kernelcache Analysis

```bash
# Extract and analyze kernel function
ipsw download ipsw --device iPhone15,2 --latest --kernel
ipsw extract --kernel *.ipsw
ipsw macho disass kernelcache.* --symbol "_panic" --dec --dec-llm copilot

# Analyze KEXT with context
ipsw macho disass kernelcache --fileset-entry com.apple.driver.AppleMobileFileIntegrity --entry --dec
```

### dyld_shared_cache Analysis

```bash
# Analyze specific virtual address
ipsw dsc disass dyld_shared_cache_arm64e --vaddr 0x1234567890 --dec

# Decompile with symbol context
ipsw dsc disass dyld_shared_cache_arm64e --symbol "_objc_msgSend" --demangle --dec

# Swift function analysis
ipsw dsc disass dyld_shared_cache --vaddr 0x... --dec --dec-lang "Swift" --dec-llm "claude"
```

## 💡 Example Output

### Input Assembly
```armasm
; Function: _main
0x100003f80: sub sp, sp, #0x20
0x100003f84: stp x29, x30, [sp, #0x10]
0x100003f88: add x29, sp, #0x10
0x100003f8c: str w0, [sp, #0xc]
0x100003f90: str x1, [sp]
0x100003f94: adrp x0, 0x100004000
0x100003f98: add x0, x0, #0x0
0x100003f9c: bl 0x100003fc0
```

### AI Decompiled Output (ObjC)
```objc
int main(int argc, char *argv[]) {
    @autoreleasepool {
        __set_user_dir_suffix(@"com.apple.apsd");

        @autoreleasepool {
            APSDaemon *daemon = [[APSDaemon alloc] init];

            if (daemon) {
                NSRunLoop *runLoop = [NSRunLoop currentRunLoop];
                [runLoop run];
                [runLoop release];
            }

            [daemon release];
        }

        return 0;
    }

    @catch (NSException *exception) {
        if ([exception reason] == 1) {
            id exceptionObj = [exception retain];
            id logger = [APSLog daemon];

            if (_os_log_type_enabled(logger, 0x11)) {
                [exceptionObj logWithLogger:logger];
            }

            [logger release];
            [exceptionObj release];
        }
    }
}
```

## 🔍 Advanced Features

### Language Detection
The AI decompiler automatically detects the programming language, but you can override:

```bash
# Force specific language interpretation
--dec-lang "C"              # Pure C code
--dec-lang "C++"            # C++ with classes
--dec-lang "Objective-C"    # ObjC with NSObject, etc.
--dec-lang "Swift"          # Swift syntax
```

### Model Selection
```bash
# Interactive model selection (no --dec-model specified)
ipsw macho disass binary --dec --dec-llm openai
? Select model to use:
  ▸ gpt-4-1106-preview
    gpt-4
    gpt-3.5-turbo-1106
    gpt-3.5-turbo

# Direct model specification
ipsw macho disass binary --dec --dec-model "Claude 3.5 Sonnet" --dec-llm copilot
```

### Context Enhancement
```bash
# Include symbol information for better context
ipsw macho disass binary --symbol "functionName" --dec --demangle

# Include multiple functions for context
ipsw macho disass binary --vaddr 0x1000 --size 200 --dec
```

## 🎯 Best Practices

### 1. **Choose the Right Model**
- **GPT-4/Claude 3.5**: Best overall quality, understands complex code patterns
- **GPT-3.5**: Faster, good for simple functions
- **Gemini**: Good balance of speed and quality
- **Local models**: Privacy-focused but require powerful hardware

### 2. **Provide Context**
```bash
# Better: Include symbol names and demangling
ipsw macho disass binary --symbol "_objc_msgSend" --demangle --dec

# Best: Include surrounding code for context
ipsw macho disass binary --vaddr 0x1000 --size 500 --dec
```

### 3. **Language Hints**
```bash
# When analyzing ObjC runtime functions
ipsw dsc disass cache --symbol "_objc_msgSend" --dec --dec-lang "Objective-C"

# When analyzing Swift compiled code
ipsw dsc disass cache --symbol "swift_" --dec --dec-lang "Swift"
```

### 4. **Performance Tips**
- Use `--dec-model` to avoid interactive selection for automation
- Cache results locally for repeated analysis
- Start with smaller code snippets before analyzing large functions

## 🛠️ Integration Examples

### Automated Analysis Script
```bash
#!/bin/bash
# Analyze all exported functions in a binary
for symbol in $(ipsw macho info binary --symbols | grep "T _" | cut -d' ' -f3); do
    echo "Analyzing $symbol..."
    ipsw macho disass binary --symbol "$symbol" --dec --dec-model "Claude 3.5 Sonnet" > "analysis_$symbol.txt"
done
```

### Custom Workflow
```bash
# 1. Extract and analyze iOS kernel panic function
ipsw download ipsw --device iPhone15,2 --latest --kernel
ipsw extract --kernel *.ipsw
ipsw macho disass kernelcache.* --symbol "_panic" --dec --dec-llm copilot

# 2. Analyze specific iOS framework function
ipsw dsc extract dyld_shared_cache_arm64e --dylib Foundation
ipsw macho disass Foundation --symbol "NSStringFromClass" --dec --dec-lang "Objective-C"
```

## 🔍 Troubleshooting

### Common Issues

**"No API key found"**
- Ensure environment variables are set correctly
- For Copilot, verify the config files exist in `~/.config/github-copilot/`

**"Model not available"**
- Check model names with `ipsw macho disass --dec --dec-llm provider` (without --dec-model)
- Verify your API plan includes the requested model

**"Poor decompilation quality"**
- Try a more powerful model (GPT-4, Claude 3.5)
- Provide more context with `--size` parameter
- Use `--demangle` for C++ symbols
- Specify the correct `--dec-lang`

**"Rate limiting"**
- Add delays between requests for large-scale analysis
- Consider using local models for extensive analysis
- Check your API plan limits

---

The AI decompiler transforms binary reverse engineering from assembly reading into understanding high-level algorithms and program logic. Combined with ipsw's comprehensive Apple platform analysis tools, it provides unprecedented insight into iOS and macOS internals.