---
hide_table_of_contents: true
description: Using the AI decompiler.
---

# AI Decompiler

## Requirements

There are currently 6 supported LLM providers

- Github Copilot
- OpenAI
- Claude (Anthropic)
- Gemini (Google AI)
- Ollama (local LLMs)
- OpenRouter (API access to multiple models)

### Github Copilot

To use the `copilot` provider you will need an accout which you can sign up for here https://github.com/features/copilot

:::info note
Here is a list of all the FREE models available https://docs.github.com/en/copilot/about-github-copilot/plans-for-github-copilot#models
:::

:::info note
After you signup for Copilot make sure you goto https://github.com/settings/copilot and enable all the models or they won't be usable and won't show up in the model listing.
:::

Once you signed up for an account you need to login with one of:

- [Zed](https://zed.dev) via [Zed Setup Guide](https://zed.dev/docs/assistant/configuration?highlight=copilot#github-copilot-chat) *(easiest in my opinion)*
  - Open the Agent Panel (Command+?)
  - Open the Settings (Option+Command+C)
  - Sign in to Github Copilot Chat
- [XCode](https://developer.apple.com/xcode/) via [Xcode Setup Guide](https://docs.github.com/en/copilot/managing-copilot/configure-personal-settings/installing-the-github-copilot-extension-in-your-environment?tool=xcode)

This should have created a folder `~/.config/github-copilot/` with either an `apps.json` or a `hosts.json` file which is what `ipsw` needs to generate an API key to use your Copilot account.

:::info note
In my opinion Copilot is the best option because it is the cheapest *(at the time of writing this)* and the FREE option is amazing, you get ALL the best models to play with AND you can also use it with VSCode, Xcode and Zed when not decompiling and just coding. 😎
:::

:::warning note
It appears that you can't use VSCode editor to create the required JSON file as they are now stored 'securely' somewhere else.
:::

### OpenAI

You must signup for and buy some API credits from https://platform.openai.com/api-keys first. Then generate an API key and put it in your environment as `OPENAI_API_KEY` and `ipsw` will auto-detect this and use it via the `--dec-llm openai` provider.

### Claude (Anthropic)

You must signup for and buy some API credits from https://console.anthropic.com/login first. Then generate an API key and put it in your environment as `ANTHROPIC_API_KEY` and `ipsw` will auto-detect this and use it via the `--dec-llm claude` provider.

### Gemini (Google AI)

Head to https://aistudio.google.com/apikey login and create an API key and put it in your environment as `GEMINI_API_KEY` and `ipsw` will auto-detect this and use it via the `--dec-llm gemini` provider.

### Ollama (local LLMs)

Install [ollama](https://ollama.com) and download a few popular models *(maybe `qwen3` or `llama4`)* and as long as the `ollama` server is running you will be able to use the `--dec-llm ollama` provider.

:::warning note
I personally have NEVER gotten usable results from a local LLM, but maybe some of you have BEEFY machines and can run the 200B+ parameter models, my laptop would just self-destruct if I tried 💻🔥
:::

### OpenRouter (API access to multiple models)

OpenRouter provides API access to a variety of models from different providers (OpenAI, Anthropic, Google, Meta, etc.) through a unified API.

You must signup for and buy some API credits from https://openrouter.ai/ first. Then generate an API key and put it in your environment as `OPENROUTER_API_KEY` and `ipsw` will auto-detect this and use it via the `--dec-llm openrouter` provider.

Optionally, set `OPENROUTER_CLIENT_TITLE` to identify your application in requests when reviewing credit usage activity.


## Getting Started

There are 2 `ipsw` disassemblers:

- `ipsw macho disass` *(for single MachOs, including file-entries in the NEW kernelcaches)*
- `ipsw dsc disass` *(for dylibs in the dyld_shared_cache)*

### `macho`

```bash
❱ ipsw macho disass /System/Library/PrivateFrameworks/ApplePushService.framework/apsd --entry \
             --dec --dec-model "Claude 3.7 Sonnet" --dec-llm "copilot"
   • Loading symbol cache file...
   • Decompiling... 🕒
```
```cpp
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

:::info note
If you don't supply a `--dec-model` `ipsw` will query the llm provider and present you with a list of all available models to choose from.
:::

### `dsc`

```bash
❱ ipsw dsc disass 22F5068a__iPhone17,1/dyld_shared_cache_arm64e --vaddr 0x2532DB6C8 --demangle \
             --dec --dec-lang "Swift" --dec-llm "openai"
   • Loading symbol cache file...
? Select model to use: gpt-4.1-2025-04-14
   • Decompiling... 🕒
```
```swift
func isLockdownModeEnabled() -> Bool {
    // Equivalent to: static var onceToken; static var globalEnabled: UInt8
    struct Static {
        static var onceToken: Int = 0
        static var globalEnabled: UInt8 = 0
    }

    // Equivalent to: swift_once(&onceToken) { ... }
    if Static.globalEnabled == 0 {
        // Run once initialization
        // Get NSUserDefaults.standardUserDefaults()
        let userDefaults = UserDefaults.standard

        // Key: "LDMGlobalEnabled"
        let key = "LDMGlobalEnabled"

        // Try to get value from global domain
        let value = userDefaults.object(forKey: key, inDomain: UserDefaults.globalDomain)

        // Try to cast to Bool
        let enabled: Bool
        if let boolValue = value as? Bool {
            enabled = boolValue
        } else {
            // Fallback: call helper (sub_2532db620) to get default value
            enabled = getDefaultLDMGlobalEnabled()
        }

        Static.globalEnabled = enabled ? 1 : 0
    }

    // Return the cached value
    return Static.globalEnabled != 0
}

// Helper for fallback (sub_2532db620)
func getDefaultLDMGlobalEnabled() -> Bool {
    // Implementation not shown; likely returns false or a default value
    return false
}
```

:::info note
You can supply `--dec-lang Swift` to force the LLM to interpret the ASM as Swift *(if it doesn't auto-detect the correct language)*
:::