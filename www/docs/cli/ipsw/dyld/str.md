---
id: str
title: str
hide_title: true
hide_table_of_contents: true
sidebar_label: str
description: Search dyld_shared_cache for string
---
## ipsw dyld str

Search dyld_shared_cache for string

```
ipsw dyld str <DSC> [STRING...] [flags]
```

### Examples

```bash
  # Perform FAST byte search for string in dyld_shared_cache
  ❯ ipsw dsc str DSC "string1"
  # Perform FAST byte search for multiple strings in dyld_shared_cache
  ❯ ipsw dsc str DSC "string1" "string2"
  # Perform FAST byte search for strings from stdin in dyld_shared_cache
  ❯ cat strings.txt | ipsw dsc str DSC
  # Perform SLOW regex search for string in dyld_shared_cache
  ❯ ipsw dsc str DSC --pattern "REGEX_PATTERN"
```

### Options

```
  -h, --help             help for str
  -p, --pattern string   Regex match strings (SLOW)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color        disable colorize output
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw dyld](/docs/cli/ipsw/dyld)	 - Parse dyld_shared_cache

