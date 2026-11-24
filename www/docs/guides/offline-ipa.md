---
description: Download a licensed IPA and decrypt it with authorization exported from your Mac.
---

# IPA decryption

App Store apps ship encrypted, so tools such as `ipsw class-dump` and
`ipsw macho disass` cannot read their code. `ipsw` can download an app and
decrypt it.

Decryption needs two things that belong to the same Apple ID:

- a licensed IPA, which is the app as the App Store delivers it to an account,
  still encrypted
- an authorization file exported from a Mac that is signed in to the App Store

Downloading needs an Apple Silicon Mac. Decryption is offline and also runs on
Linux.

| Step | Command | Runs on |
| --- | --- | --- |
| Export the authorization | `ipsw macho export-auth` | Apple Silicon Mac, macOS 26 or later |
| Download a licensed IPA | `ipsw download ipa --online` | Apple Silicon Mac |
| Decrypt | `ipsw macho decrypt-ipa` | Apple Silicon Mac with macOS 26 or later, Linux arm64, Linux x86-64 |

## Before you start

- The Mac must already be signed in to the App Store with the Apple ID that
  owns the app. `export-auth` copies authorization that exists on the Mac. It
  does not sign in, and it cannot create a record the Mac does not have.
- The authorization file holds a record per Apple ID and nothing per app. Use
  one Apple ID for the export and the download. With an export from another
  Apple ID the decryption fails and writes nothing.
- Downloads use `ipsw download ipa --online`, called the online route below. It
  works for free apps only.
- The online route has its own sign-in, `ipsw download ipa signin`. That saves
  a session for downloads and does not create the authorization file.
- A decrypted IPA is not installable as it is. Decryption does not replace the
  app's signing or provisioning requirements.

## Export the authorization

Run the export as your normal user from an interactive terminal. The command
requests sudo approval for its own short-lived helper, so do not run the whole
command with sudo.

```sh
ipsw macho export-auth
```

The export creates `~/.config/ipsw/fairplay/authorization.fpauth`. Pass
`--output DIR` to use another directory. The directory must be owned by you
with mode `0700`, and the authorization file has mode `0600`. An existing
authorization file is never overwritten, so move the old one away before you
export again.

An export keeps working for later downloads made with the same Apple ID. If a
newer download fails with `matching license record was not found` although the
Apple ID is right, export again.

Keep this file private. Together with a licensed IPA it is all that decryption
needs, on any machine.

## Download a licensed IPA

Check that your build has the online route. The command prints `available`:

```sh
ipsw download ipa setup --check
```

Unset `APPSTORE_GUID`, `APPSTORE_PROXY`, `APPSTORE_REDOWNLOAD`, `APPSTORE_UA`
and `IPSW_ANISETTE_URL` first. The online route refuses to run while any of
them is set. It also rejects `--password`, `--search`, `--store-front`,
`--proxy`, `--insecure`, `--sms` and `--vault-password`.

Prepare the local state once. Setup downloads six files from Apple (about
300 MB), keeps them in `~/.config/ipsw/fairplay/images` and reuses them on
later runs. To use local copies, pass `--images DIR` to setup, signin and the
download. Setup still contacts Apple's provisioning service in that case, so it
cannot run offline.

```sh
ipsw download ipa setup
```

Sign in. `ipsw` asks for your Apple ID, then your password at a hidden prompt,
then a verification code if Apple requests one. The Apple ID and password
prompts wait ten minutes and the code prompt waits two. A prompt that times out
submits nothing. The session is saved in the Keychain item
`ipsw fairplay session`.

```sh
ipsw download ipa signin
```

For a script, name the Apple ID and pipe the password. This example reads it
from a Keychain item of your own, here called `appleid`:

```sh
security find-generic-password -s appleid -w | ipsw download ipa signin --username user@example.com --password-stdin
```

Download by bundle ID. `ipsw` prints the path after `Licensed IPA:`.

```sh
ipsw download ipa --online --output ./apps com.example.app
```

If the account does not own the app yet, the download stops with
`license absent; purchase requires explicit consent`. Add `--purchase` to get
the free license. If the saved sign-in is older than three minutes, `ipsw`
signs in again before it sends the purchase request, so expect the password
prompt or pipe the password with `--password-stdin`.

```sh
ipsw download ipa --online --purchase --output ./apps com.example.app
```

## Decrypt

Give `decrypt-ipa` the licensed IPA. The authorization is read from
`~/.config/ipsw/fairplay/authorization.fpauth` unless you pass `--auth FILE`.

```sh
ipsw macho decrypt-ipa ./apps/LicensedApp.ipa --output ./decrypted
```

Successful decryption writes `decrypted/repacked.ipa` and leaves the input IPA
unchanged. Decrypting into the same directory again replaces the earlier
result.

### Download and decrypt in one command

`--decrypt` decrypts right after the download. It reads the authorization from
`~/.config/ipsw/fairplay/authorization.fpauth` only.

```sh
ipsw download ipa --online --decrypt --output ./apps com.example.app
```

The `--output` folder receives the licensed IPA only. The decrypted
`repacked.ipa` goes to a new directory under
`~/.config/ipsw/fairplay/generations`, and `ipsw` prints that directory after
`Decrypted IPA:`. Each run adds a directory about the size of the app and
nothing removes the old ones, so delete those you no longer need. Use
`decrypt-ipa` when you want to choose where the result goes.

## Decrypt on another machine

The authorization file is not tied to the Mac that exported it. Copy it and the
licensed IPA to another Apple Silicon Mac or to a Linux machine and decrypt
there. On Linux, use the static build for your architecture, arm64 or x86-64.
Only the decryption runs on Linux: the export and the download need the Mac.

The export must still come from a Mac signed in to the Apple ID that owns the
app. An export from a Mac signed in to a different Apple ID fails with
`matching license record was not found`, wherever you run the decryption.

Transfer the file only to a machine you control. After copying it, restore the
permissions as its owner:

```sh
chmod 700 ~/.config/ipsw/fairplay
chmod 600 ~/.config/ipsw/fairplay/authorization.fpauth
```

Then decrypt as above:

```sh
ipsw macho decrypt-ipa ./LicensedApp.ipa --output ./decrypted
```

## Troubleshooting

The decryption errors are short on purpose: they name no path and no account.
`offline processing failed` is the catch-all. When a decryption fails, work
through these in order.

1. Check the version with `ipsw version`. Version 3.1.746 failed with
   `offline processing failed` when started through Homebrew's
   `/opt/homebrew/bin/ipsw` link, and on Linux. Both were fixed in 3.1.747.
   Versions before 3.1.751 report a rejected output location or IPA as
   `offline processing failed` or
   `offline operation could not read or write its files`.
2. Check the Apple ID. The export must come from a Mac signed in to the App
   Store with the Apple ID that owns the app. A wrong Apple ID reports
   `matching license record was not found`. So does an export that lacks the
   key this download needs, so if the Apple ID is right, export again.
3. Check the output path. The directory that will contain the output must be a
   real directory, owned by you and not writable by your group or by others.
   Otherwise the decryption is refused before any work starts, with
   `output location was rejected`. On macOS `/tmp` and `/var` are symbolic
   links, so `--output /tmp/result` is refused. Only the immediate parent is
   checked, so a directory you created inside `/tmp` works as the parent, and
   so does your home folder.
4. Check the inputs. The IPA must be a regular file, not a symbolic link, and
   no larger than 4 GiB; otherwise the error is `input IPA was rejected`. The
   authorization file must be a regular file with mode `0600` exactly, and its
   directory needs mode `0700` exactly and must not be a symbolic link.

| Message | Cause |
| --- | --- |
| `matching license record was not found` | The exported authorization has no record for the IPA's Apple ID, or has the record without the key this IPA needs. Export on a Mac signed in to the App Store with the Apple ID that owns the app. If the Apple ID is right, export again. |
| `output location was rejected` | The directory that will contain the output is a symbolic link (as `/tmp` and `/var` are on macOS), is not a directory, belongs to another user, or is writable by group or others. |
| `input IPA was rejected` | The IPA is a symbolic link, is not a regular file, or is larger than 4 GiB. |
| `offline processing failed` | The catch-all for a failure that has no message of its own. `ipsw` 3.1.746 reported it for every decryption started through Homebrew's link or on Linux. |
| `offline operation could not read or write its files` | The IPA, the authorization file or the directory that will contain the output is missing, or a file could not be created in the output directory. |
| `authorization access or file permissions were rejected` | The authorization file or its directory is a symbolic link, or the modes are not exactly `0600` for the file and `0700` for its directory. Also reported when the system denies writing the output. |
| `platform or input format is not supported` | `export-auth` was run on Linux; it runs on macOS only. From `decrypt-ipa`: the authorization file is damaged or is not an authorization file, or the IPA uses a license version that is not supported. |
| `authorization.fpauth already exists; existing files are never overwritten` | Move the old file away, or export to another directory with `--output`. |
| `authorization export requires an interactive terminal for sudo approval` | Run `export-auth` in a terminal, not from a script or a job runner. |
| `authorization directory must be owned by the current user with mode 0700` | Fix the directory's owner and mode. |
| `authentication required; sign in explicitly` | Run `ipsw download ipa signin`. |
| `offline decryption is unavailable in this build` | This build has no decryption support. Use a release build for a platform in the table at the top. |
