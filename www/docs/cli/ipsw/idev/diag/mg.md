---
id: mg
title: mg
hide_title: true
hide_table_of_contents: true
sidebar_label: mg
description: Query MobileGestalt
---
## ipsw idev diag mg

Query MobileGestalt

```
ipsw idev diag mg [flags]
```

### Examples

```
❯ ipsw idev diag mg -k SupplementalBuildVersion,ProductVersionExtra | jq .

	{
		"status": "Success",
		"diagnostics": {
		  "MobileGestalt": {
			"ProductVersionExtra": "(a)",
			"Status": "Success",
			"SupplementalBuildVersion": "20C7750490e"
		  }
		}
	  }
```

### Options

```
  -h, --help[=true|false]   help for mg
  -k, --keys strings        Keys to retrieve (can be csv)
```

### Options inherited from parent commands

```
      --color[=true|false]      colorize output
      --config string           config file (default is $HOME/.config/ipsw/config.yaml)
      --no-color[=true|false]   disable colorize output
  -u, --udid string             Device UniqueDeviceID to connect to
  -V, --verbose[=true|false]    verbose output
```

### SEE ALSO

* [ipsw idev diag](/docs/cli/ipsw/idev/diag)	 - Diagnostics commands

