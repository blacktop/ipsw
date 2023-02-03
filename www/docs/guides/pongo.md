---
description: PongoOS shell
hide_table_of_contents: false
---

# PongoOS

> `ipsw pongo` is a tool to interact with the PongoOS shell.

## Requirements

Setup your device to boot to [PongoOS](https://github.com/checkra1n/PongoOS)

- Put your [checkm8-able](https://github.com/axi0mX/ipwndfu) *AND* [blackbird-able](https://www.theiphonewiki.com/wiki/Blackbird_Exploit) device into DFU mode.
- Run [checkra1n](https://checkra.in) via the following CLI command:

```bash
❯ /Applications/checkra1n.app/Contents/MacOS/checkra1n -cp
```

:::info
The only devices that are checkm8-able and blackbird-able are **A10**/**T2** devices.
:::

:::info
Right now `ipsw pongo` can only decrypt the keybags/im4p firmwares in local/remote IPSW/OTAs, but in the future it will be able to do more.
:::


## Decrypting keybags

Now we can run `ipsw pongo` to interact with the PongoOS shell.

```bash
❯ ipsw pongo iPad_64bit_TouchID_ASTC_16.3_20D47_Restore.ipsw
      • Decrypting Keybag         file=LLB.ipad6f.RELEASE.im4p
      • Decrypting Keybag         file=LLB.ipad7b.RELEASE.im4p
      • Decrypting Keybag         file=LLB.j71t.RELEASE.im4p
      • Decrypting Keybag         file=LLB.j72t.RELEASE.im4p
      • Decrypting Keybag         file=iBoot.ipad6f.RELEASE.im4p
      • Decrypting Keybag         file=iBoot.ipad7b.RELEASE.im4p
      • Decrypting Keybag         file=iBoot.j71t.RELEASE.im4p
      • Decrypting Keybag         file=iBoot.j72t.RELEASE.im4p
      • Decrypting Keybag         file=sep-firmware.j71b.RELEASE.im4p
      • Decrypting Keybag         file=sep-firmware.j71s.RELEASE.im4p
      • Decrypting Keybag         file=sep-firmware.j71t.RELEASE.im4p
      • Decrypting Keybag         file=sep-firmware.j72b.RELEASE.im4p
      • Decrypting Keybag         file=sep-firmware.j72s.RELEASE.im4p
      • Decrypting Keybag         file=sep-firmware.j72t.RELEASE.im4p
      • Decrypting Keybag         file=iBEC.ipad6f.RELEASE.im4p
      • Decrypting Keybag         file=iBEC.ipad7b.RELEASE.im4p
      • Decrypting Keybag         file=iBEC.j71t.RELEASE.im4p
      • Decrypting Keybag         file=iBEC.j72t.RELEASE.im4p
      • Decrypting Keybag         file=iBSS.ipad6f.RELEASE.im4p
      • Decrypting Keybag         file=iBSS.ipad7b.RELEASE.im4p
      • Decrypting Keybag         file=iBSS.j71t.RELEASE.im4p
      • Decrypting Keybag         file=iBSS.j72t.RELEASE.im4p
   • Writing keybags to 20D47__iPad6,11_12_iPad7,5_6/kbags.json
```   

```bash
❯ cat 20D47__iPad6,11_12_iPad7,5_6/kbags.json | jq . | head -n31
```

```json
{
  "type": "IPSW",
  "version": "16.3",
  "build": "20D47",
  "devices": [
    "iPad6,11",
    "iPad7,5",
    "iPad7,6",
    "iPad6,12"
  ],
  "files": [
    {
      "name": "LLB.ipad6f.RELEASE.im4p",
      "kbags": [
        {
          "type": "prod",
          "iv": "18ff771931372ebd03ad7537cba34517",
          "key": "be88446944620af807a6a0f64234d46437355b016030cbe729fe892e95283e29"
        },
        {
          "type": "dev",
          "iv": "5765ce9fbd5707be023ebfcd7ce3c55e",
          "key": "7885dabe10477aa446ac5fd92dce8694d10b9bc05c80f5e966f11a1a9377553f"
        },
        {
          "type": "dec",
          "iv": "<REDACTED>",
          "key": "<REDACTED>"
        }
      ]
    },
<SNIP>
```

Extract ALL the im4p files from the IPSW

```bash
❯ ipsw extract --pattern '.*im4p$' iPad_64bit_TouchID_ASTC_16.3_20D47_Restore.ipsw
```

Decrypt the SEP firmware

```bash
❯ ipsw img4 dec --iv-key <REDACTED> sep-firmware.j71b.RELEASE.im4p
      • Decrypting file to sep-firmware.j71b.RELEASE.im4p.dec
```

And WIN.

```bash
❯ hexdump -C -s 65578 -n 16 sep-firmware.j71b.RELEASE.im4p.dec

0001002a  42 75 69 6c 74 20 62 79  20 6c 65 67 69 6f 6e 32  |"Built by legion2"|
```

## Decrypting LOCAL im4p files

This will also extract the im4p files from the IPSW and decrypt them using the decrypted keybags.

```bash
❯ ipsw pongo --decrypt iPad_64bit_TouchID_ASTC_16.3_20D47_Restore.ipsw
```

## Decrypting REMOTE im4p files

This will also extract the im4p files from the URL using and decrypt them using the decrypted keybags.

```bash
❯ ipsw pongo --decrypt --remote \
      https://updates.cdn-apple.com/iPad_Pro_HFR_16.1_20B82_Restore.ipsw
```