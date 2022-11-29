---
id: mg
title: mg
hide_title: true
hide_table_of_contents: true
sidebar_label: mg
description: Query MobileGestalt
last_update:
  date: 2022-11-29T11:50:35-07:00
  author: blacktop
---
## ipsw idev diag mg

Query MobileGestalt

```
ipsw idev diag mg [flags]
```

### Examples

```bash
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
  -h, --help           help for mg
  -k, --keys strings   Keys to retrieve (can be csv)
```

### Options inherited from parent commands

```
      --color           colorize output
      --config string   config file (default is $HOME/.ipsw.yaml)
  -u, --udid string     Device UniqueDeviceID to connect to
  -V, --verbose         verbose output
```

### SEE ALSO

* [ipsw idev diag](/docs/cli/ipsw/idev/diag)	 - Diagnostics commands

