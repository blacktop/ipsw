---
description: Analyze Dylibs in DSC with IDA Pro.
---

# Analyze Dylibs in DSC with IDA Pro

## Introduction

> This command is intended to automate generating .idb(s) for dylibs in the DSC with IDA Pro.

In addition to loading a selected dylib *(and any addition dylibs supplied as arguments)* into IDA Pro *(in single module mode)*, it will also:
- Generates an IDAPython script to load sane default support dylibs and analyze ObjC info
- Generates a descriptive name for the compressed IDB file output
- Allows you to slide the dylib in memory to a specific address with the `--slide` flag to match an `lldb` session or `crashlog`
- Load all the of dependancies of a given dylib with the `--dependancies` or `-d` flag
- If you just want to peek at a dylib you can use the `--enable-gui` flag to open the IDB in IDA Pro GUI with the `--temp-db` flag to prevent IDA Pro from creating a new IDB file
- Create a log file of the IDA Pro output with the `--log` flag
- Want you run your own IDA Pro script?  Use the `--script` flag and the `--script-args` flag to pass arguments to your script
- **COMING SOON** - Load all the GOTs and stubs for a given dylib and the sane defaults

## Running with host IDA Pro

To prep an IDA Pro session to analyze the `Email` dylib in the DSC

```bash
❯ ipsw dyld ida dyld_shared_cache_arm64e Email --enable-gui --delete-db
```

This will open the `Email` dylib in the IDA Pro GUI and load the sane default support dylibs and analyze ObjC info in a few minutes.

### Trouble Shooting 🤔

#### Add the `-V` verbose flag to see stdout/stderr from IDA Pro.

A possible error could be that you are trying to analyze your systems DSC in a read-only folder and IDA Pro can't create it's IDB there so you'll need to supply the `--output` flag to specify a writable folder for IDBs and logs.

Another possible error I've seen is if you are using an older version of IDA Pro that doesn't support the newer DSC format it will fail.  For example if you are using IDA Pro 7.x and try to analyze a DSC from iOS 16.x it will fail etc.

## Running with Docker

:::note
This requires that you have built a **licensed** version of IDA Pro for Docker.
:::

#### Prep host for **docker** GUI application support *(on macOS)*

1. Install XQuartz `brew install --cask xquartz`
2. `open -a XQuartz` and make sure you **"Allow connections from network clients"** in the Security tab
3. Now add the IP using Xhost with: `xhost + 127.0.0.1` or `xhost + $(ipconfig getifaddr en0)`

### Building IDA Pro for Docker

```bash
❯ git clone https://github.com/blacktop/docker-idapro.git
❯ cd docker-idapro
```

1) Put a copy of the **linux** installer in the `pro` folder and name it `idapro.run`

```bash
IDAPW="put-your-install-pw-here" make build-pro
```

2) Enter image container:

```bash
make ssh-pro
```

```bash
root@add3b0fd6966:/ida# ./ida64
```

3) This will open the GUI; now accept the license agreement and set any settings you want to persist and close the window.

4) Rebuild the IDA Pro image with the new `ida.reg` file:

```bash
make build-reg
```

This will create a new image called `blacktop/ida:8.2-pro`  

You can change that name with:

```bash
❯ docker tag blacktop/ida:8.2-pro YOUR_ORG/ida:8.2-pro-licensed`
```

and then push that to your private registry.

Congratulations!  You now have a registered IDA Pro image that you can perform headless analysis with 🎉

### Running *headless* in Docker

```bash
❯ ipsw dyld ida dyld_shared_cache_arm64e Email --delete-db --output . \
                     --docker --docker-image blacktop/idapro:8.2-pro
   • Starting IDA Pro...
   • 🎉 Done!                   db=DSC_Email_iOS_15.7.i64
```

About `4m 37s` later...

```bash
❯ ll DSC_Email_iOS_15.7.i64
-rw-r--r--  1 blacktop  staff   "183M" Mar 13 12:23 DSC_Email_iOS_15.7.i64
```

Now an analyst can open the ready to go `DSC_Email_iOS_15.7.i64` file in IDA Pro and start analyzing the dylib.