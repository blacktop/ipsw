---
description: Download an App Store app and decrypt it.
---

# IPA decryption

App Store apps ship encrypted, so tools such as `ipsw class-dump` and
`ipsw macho disass` cannot read their code. `ipsw` can download an app and
decrypt it.

:::info
Downloading and exporting need an Apple Silicon Mac that is signed in to the
App Store with the Apple ID that owns the app. Exporting needs macOS 26 or
later. Downloads work for free apps only.
:::

## Quick start

Export the Mac's App Store authorization. You do this once.

```bash
❯ ipsw macho export-auth
```

Download an app and decrypt it

```bash
❯ ipsw download ipa --decrypt --output ./apps com.example.app
```

The first download fetches Apple's support files (about 300 MB) and asks for
your Apple ID, your password and a verification code if Apple requests one.
Later downloads reuse the saved session.

`./apps` receives the IPA as the App Store delivers it and, beside it, the
decrypted copy with the suffix `.decrypted.ipa`.

:::note
A decrypted IPA is not installable as it is. Decryption does not replace the
app's signing or provisioning requirements.
:::

## The two sign-ins

- `ipsw macho export-auth` copies the authorization that decrypts apps. It
  comes from the Mac's own App Store sign-in; the command does not sign in.
- `ipsw download ipa` has its own sign-in, which only downloads.

Use the same Apple ID for both. With an export from another Apple ID the
decryption fails and writes nothing.

## Export the authorization

Run the export as your normal user from an interactive terminal. It requests
sudo approval for its own short-lived helper, so do not run the whole command
with sudo.

```bash
❯ ipsw macho export-auth
```

This creates `~/.config/ipsw/fairplay/authorization.fpauth`. Pass
`--output DIR` to use another directory. An existing file is never
overwritten, so move the old one away before you export again.

:::warning
Keep this file private. Together with an IPA from the same Apple ID it is all
that decryption needs, on any machine.
:::

## Download

Download by bundle ID

```bash
❯ ipsw download ipa --output ./apps com.example.app
```

If the account does not own the app yet, add `--purchase` to get the free
license. Apple accepts only a recent sign-in for this, so `ipsw` may ask for
your password again.

```bash
❯ ipsw download ipa --purchase --output ./apps com.example.app
```

See the [download guide](/docs/guides/download#download-ipa) for searching and
for signing in from a script.

## Decrypt an IPA you already have

```bash
❯ ipsw macho decrypt-ipa ./apps/Example.ipa --output ./decrypted
```

This writes `./decrypted/repacked.ipa` and leaves the input unchanged. Without
`--output` the result goes to the current directory. The authorization is read
from `~/.config/ipsw/fairplay/authorization.fpauth` unless you pass
`--auth FILE`.

## Decrypt on another machine

The authorization file is not tied to the Mac that exported it. Copy it and
the IPA to another Apple Silicon Mac or to a Linux machine (arm64 or x86-64)
and decrypt there. Only the decryption runs on Linux.

Restore the permissions after copying, then decrypt as above

```bash
❯ chmod 700 ~/.config/ipsw/fairplay
❯ chmod 600 ~/.config/ipsw/fairplay/authorization.fpauth
❯ ipsw macho decrypt-ipa ./Example.ipa --output ./decrypted
```

## Troubleshooting

The decryption errors are short on purpose: they name no path and no account.

| Message | What to do |
| --- | --- |
| `matching license record was not found` | The export has no record for the IPA's Apple ID, or lacks the key this download needs. Export on a Mac signed in to the App Store with the Apple ID that owns the app. If the Apple ID is right, export again. |
| `output location was rejected` | The directory that will contain the output must be a real directory, owned by you and not writable by your group or by others. On macOS `/tmp` and `/var` are symbolic links, so `--output /tmp/result` is refused; a directory you created inside `/tmp` works as the parent. |
| `input IPA was rejected` | The IPA must be a regular file, not a symbolic link, and no larger than 4 GiB. |
| `authorization access or file permissions were rejected` | The authorization file needs mode `0600` and its directory mode `0700`, exactly. Neither may be a symbolic link. |
| `offline operation could not read or write its files` | The IPA, the authorization file or the directory that will contain the output is missing. |
| `platform or input format is not supported` | The authorization file is damaged, or the IPA uses a license version that is not supported. `export-auth` reports it on Linux. |
| `offline processing failed` | A failure with no message of its own. Update `ipsw` first: early releases of this feature reported it for every decryption. |
| `authorization.fpauth already exists; existing files are never overwritten` | Move the old file away, or export to another directory with `--output`. |
| `authorization export requires an interactive terminal for sudo approval` | Run `export-auth` in a terminal, not from a script or a job runner. |
| `the environment variable … is set; unset it and try again` | Downloads refuse to run while `APPSTORE_GUID`, `APPSTORE_PROXY`, `APPSTORE_REDOWNLOAD`, `APPSTORE_UA` or `IPSW_ANISETTE_URL` is set. |
| `offline decryption is unavailable in this build` | Use a release build for an Apple Silicon Mac, Linux arm64 or Linux x86-64. |

`ipsw download ipa setup --check` prints `available` when your build can
download. To use your own copies of Apple's support files, pass `--images DIR`
to the download and to `setup`.
