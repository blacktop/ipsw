# ipsw symbolicate

Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)

```
ipsw symbolicate <crashlog> <dyld_shared_cache> [flags]
```

## Options

```
  -d, --demangle   Demangle symbol names
  -h, --help       help for symbolicate
  -u, --unslide    Unslide the crashlog for easier static analysis
```

## Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output
```

## See also

* [ipsw](/cmd/ipsw/)	 - Download and Parse IPSWs (and SO much more)

