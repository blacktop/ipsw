---
description: Working with Apple's NEW AEA format.
---

# AEA

## How to extract from/mount these NEW `.dmg.aea` files

- It all works seemlessly in the background so you don't have to worry about it at all.
- It will also work offline as the `latest` version of `ipsw` will always have the AEA private keys embedded.

## What if I **want** to mess with them?

### Download AEA PEMs

Download AEA PEMs from remote IPSWs

![aea-dl-pem](../../static/img/guides/aea-dl-pem.webp)

You can also pull them out of local/remote IPSWs

```bash
❯ ipsw extract --fcs-key iPhone16,2_18.0_22A5307f_Restore.ipsw
   • Extracting AEA1 DMG fcs-keys
      • Created 22A5307f__iPhone16,2/090-29713-065.dmg.aea.pem
      • Created 22A5307f__iPhone16,2/090-27454-052.dmg.aea.pem
```

Now extract one of these pesky `.dmg.aea` files

```bash
❯ ipsw extract --dmg sys iPhone16,2_18.0_22A5307f_Restore.ipsw
   • Extracting DMG
        1.50 GiB / 1.50 GiB [====================================| ✅  ] 1.50 GiB/s
        229.00 b / 229.00 b [====================================| ✅  ]
        2.04 KiB / 2.04 KiB [====================================| ✅  ]
      • Created 22A5307f__iPhone16,2/090-29713-065.dmg.aea
      • Created 22A5307f__iPhone16,2/Firmware/090-29713-065.dmg.aea.root_hash
      • Created 22A5307f__iPhone16,2/Firmware/090-29713-065.dmg.aea.trustcache
```

### Use an extracted PEM

Use an extracted PEM file to decrypt a `*.dmg.aea` file

```bash
❯ ipsw fw aea --pem '22A5307f__iPhone16,2/090-29713-065.dmg.aea.pem'
                    '22A5307f__iPhone16,2/090-29713-065.dmg.aea' --output /tmp
   • Extracted AEA to /tmp/090-29713-065.dmg
```

### Dump all the AEA metadata

Dump all the AEA metadata from a local AEA file

> This parses the AEA header and metadata and presents it for you in `--color`

![aea-info](../../static/img/guides/aea-info.webp)

### Extract the AEA Private Key

Extract the AEA private key that you can use with the `aea` binary to decrypt the `*.dmg.aea`

```bash
❯ ipsw fw aea --key iPhone16,2_18.0_22A5282m_Restore/090-27454-036.dmg.aea

'base64:S8f/KZsKuRXg/RnkMlG6SWiFtSPlmwz9YFdBnyPc1EQ='
```

Decrypt with `/usr/bin/aea`

```bash
❯ aea decrypt -i iPhone16,2_18.0_22A5282m_Restore/090-27454-036.dmg.aea
      -o TEST.dmg -key-value 'base64:S8f/KZsKuRXg/RnkMlG6SWiFtSPlmwz9YFdBnyPc1EQ='
```

You can also use `ipsw`

```bash
❯ ipsw fw aea --key-val 'base64:S8f/KZsKuRXg/RnkMlG6SWiFtSPlmwz9YFdBnyPc1EQ='
                    '22A5307f__iPhone16,2/090-29713-065.dmg.aea' --output /tmp
                    
   • Extracted AEA to /tmp/090-29713-065.dmg
```

### Download AEA PEMs as JSON "Database"

Download AEA PEMs as JSON form remote IPSWs *(using `ipsw`'s patent pending **partial-partialzip** ™️)*

![aea-dl-jsondb](../../static/img/guides/aea-dl-jsondb.webp)

:::info note
It appears that these AEA PEM keys are `unique` per release for iOS and macOS. *(So only 2 🆕 keys per release; **1** `iOS` and **1** `macOS`)*
:::

To get the `macOS` PEM JSON "Database"

```bash
❯ ipsw dl appledb --os macOS --version '15.0 beta 2' --fcs-keys-json --output /tmp --confirm
   • Querying AppleDB...
   • Parsing remote IPSW       build=24A5279h devices=UniversalMac version=15.0
   • Extracting remote AEA1 DMG fcs-keys
      • Created '/tmp/fcs-keys.json'
```

You can also dump the PEM in the JSON database from a local file

```bash
❯ ipsw fw aea --fcs-key iPhone16,2_18.0_22A5282m_Restore/090-27454-036.dmg.aea
   • Created fcs-keys.json
```
```json
{
  "C76OEoiX5Lfc0nRQtn1cLkOEwDtC8HGIM_M_1rJgQ9g=":"LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEJHMHdhd0lCQVFRZ21qWDBwYmU2WWErMDJUek4KY0laWHZ6L1VId1lMN1JwUVFka01QV1pmT2UraFJBTkNBQVRzeUsxZEJzUFJVZU15b2hWM2VJUG5JNGw2SzhjUApWeGZGRXBEd01DdXNlTUVrV0UzV0w5QXcvTTMyRk5Ta2lYZUNpQXoxMXBOdUJVWGVmTkFPSXlkSQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg=="
}
```

:::info note
This "Database" is a key-value pair JSON file where the `key` is the unique part of the `fcs-key-url` as can been seen above in the `--info` dump from a `.dmg.aea` file AND the `value` of the key-value is the base64 encoded PEM bytes.
:::

### Use AEA PEM Database

```bash
❯ ipsw mount fs --pem-db 'fcs-keys.json' iPhone16,2_18.0_22A5282m_Restore.ipsw
   • Mounted fs DMG 090-27454-036.dmg
      • Press Ctrl+C to unmount '/tmp/090-27454-036.dmg.mount' ...
```

:::info note
This `fcs-keys.json` is what I'm refering to as an *AEA PEM JSON Database* and it can be used **offline** via the `--pem-db` flag on several `ipsw` commands.  This allows you to just *update* the JSON Database instead of having to contantly download a 🆕 version of `ipsw` to use **offline** on latest `*.dmg.aea` files.
:::

### Sinkhole/Proxy Apple PEM Server

You can use [ipswd](https://blacktop.github.io/ipsw/api) to also serve the fcs-keys.json DB by adding the following to the `~/.config/ipsw/config.yml`

```yaml
daemon:
  pem-db: /path/to/fcs-keys.json
```

Start the *daemon*

```bash
ipswd start
```

The *daemon* is now hosting the route `GET /v1/aea/fcs-keys/:key`

```bash
❯ http localhost:3993/v1/aea/fcs-keys/zhYs0f2L4kS-0oTUtvLn1JZdp4YGOoLbKFBad8ui7Vo=
```
```
HTTP/1.1 200 OK
Content-Length: 241
Content-Type: application/octet-stream
Date: Wed, 10 Jul 2024 23:33:15 GMT

-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgeHM016M8mfitwIag
gsNwsYLUrNgifqq5VRdR8USWAdGhRANCAATl3LnJS5y4HbGj72pGcKpka8WbocXi
2cVY4NlhgpH5VRFwPcWtHZnoWj0hxDqB5V+b14UkPXsyelZIP91MEO8T
-----END PRIVATE KEY-----
```

You can use the above [`ipsw dl appledb`](#download-aea-pems-as-json-database) command periodically to update the `fcs-keys.json` *(which appends)* and transfer that file over to your offline system running `ipswd` to prevent needing to constantly update `ipsw` to latest etc.

Now you just need to proxy `https://wkms-public.apple.com/fcs-keys` to `http://localhost:3993/v1/aea/fcs-keys`

This works because `ipsw` will:

1) Try it's embedded PEM keys
2) Try the `--pem-db` you provided
3) Try and reach out to Apple's server to get the PEM  
   i) Which `ipswd` will happily serve to it *(if you follow the above steps)* 😎
