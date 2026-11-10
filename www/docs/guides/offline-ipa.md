---
description: Decrypt an existing licensed IPA with matching local authorization.
---

# Offline IPA decryption

This preview covers the two offline commands documented below. It can decrypt
an existing licensed IPA using matching local authorization. It does not sign
in to an account or download apps. Use an offline-IPA release build for Apple
Silicon with macOS 26 or later, or select the static Linux build matching your
machine's architecture: arm64 or x86-64.

On macOS, run the export command as your normal user from an interactive
terminal. The command requests sudo approval for its own short-lived helper;
do not run the whole command with sudo.

```sh
./ipsw macho export-auth
```

The export creates `~/.config/ipsw/fairplay/authorization.fpauth`; pass
`--output DIR` to use another directory. The directory must be owned by you
with mode `0700`; the authorization file has mode `0600`. An existing
authorization file is never overwritten. Treat this file as private account
authorization and transfer it only to a machine you control. After copying it,
restore the permissions as its owner:

```sh
chmod 700 ~/.config/ipsw/fairplay
chmod 600 ~/.config/ipsw/fairplay/authorization.fpauth
```

On macOS or Linux, provide an IPA whose license matches the exported
authorization. The authorization is read from
`~/.config/ipsw/fairplay/authorization.fpauth` unless you pass `--auth FILE`:

```sh
./ipsw macho decrypt-ipa ./LicensedApp.ipa --output ./decrypted-app
```

The output directory must not already exist. Successful decryption writes
`decrypted-app/repacked.ipa`; the input IPA is preserved. A "matching license
record was not found" error means the exported authorization does not contain
the license record required by that IPA. Decryption does not replace the app's
signing or provisioning requirements and does not make the result installable
on an arbitrary device.

