---
slug: sandbox-architecture
title: "287 vs 14: How iOS and macOS Sandbox Profiles Take Different Roads to the Kernel"
authors: [blacktop]
tags: [sandbox, kernel, macos, reversing]
draft: true
hide_table_of_contents: false
---

<!-- TODO: hero image -->

If you've ever pointed `ipsw sb list` at an iOS kernelcache, you've seen
something like 287 profile names scroll by — `com.apple.WebKit.WebContent`,
`baseline`, `nointernet`, the whole roster of system daemons. Point the same
command at a macOS kernelcache and you get… fourteen.

```
$ ipsw sb list kernelcache.release.Mac17,6
com.apple.corebrightnessd
com.apple.dext
com.apple.endpointsecurity.endpointsecurityd
com.apple.oahd-helper
com.apple.oahd-root-helper
com.apple.oahd
com.apple.opendirectoryd
com.apple.sandboxd
com.openssh.sshd
no-internet
no-network
no-write-except-temporary
no-write
pure-computation
```

That's not a parser bug. It's a deliberate architectural split, and chasing
it down through `Sandbox.kext` reveals one of the more interesting trade-offs
in Apple's security tooling: **iOS bakes its sandbox into the kernel binary;
macOS compiles it at boot.**

<!-- truncate -->

## Prior art

The Apple sandbox has been reverse-engineered in public for over a decade.
Three projects are load-bearing for anyone working in this space today:

- **Dion Blazakis — *"The Apple Sandbox"* (Black Hat DC 2011).** The paper that
  first laid out `Sandbox.kext`, the TrustedBSD policy hooks, and the shape of
  the compiled profile bytecode. Dion's companion tool,
  [`dionthegod/XNUSandbox`](https://github.com/dionthegod/XNUSandbox), is the
  repo every subsequent profile decompiler traces back to.
- **SandBlaster —
  [`malus-security/sandblaster`](https://github.com/malus-security/sandblaster).**
  The malus-security team built on Dion's work to ship a working iOS
  kernel → SBPL pipeline, tracking it through several major iOS versions.
- **Yarden Hamami / Cellebrite Labs —
  [`cellebrite-labs/sandblaster`](https://github.com/cellebrite-labs/sandblaster)
  ([talk](https://www.youtube.com/watch?v=8e1slpXAyrc)).** Yarden forked
  SandBlaster and pushed it forward through modern iOS, and gave what's still
  the best public walkthrough of the bytecode format and how it moves between
  releases.

Everything below is downstream of that work. For the first stretch of
building `ipsw sb`, I leaned on SandBlaster's output as an oracle while I
reverse-engineered the bytecode with a hex editor, `ipsw`, and IDA Pro.

## Why not just fork SandBlaster?

Two things pushed me past "fork and patch":

1. **The format moves every release, and there's no spec.** The sandbox is
   Apple-private — not a published interface, not even an internal one that
   stays still. Operation numbers shift, filter types appear and disappear,
   the encoding changes. A decompiler that's right on iOS 14 can go silently
   wrong on iOS 26, and you won't know unless something catches it.
2. **Diffing decompiled SBPL isn't proof of correctness.** Two decompilers can
   each produce SBPL that looks plausible, is self-consistent, and disagrees
   with the other. Readable text is not ground truth. The only real oracle is
   Apple's compiler itself.

So `ipsw sb` grew around roundtrip validation: take compiled bytecode,
decompile to SBPL, feed that SBPL back through `libsandbox`, diff the
resulting bytecode against the input. Anything that doesn't converge is a
bug. In practice the loop settles in 2–4 rounds for everything I've thrown at
it, and that's what finally gave me confidence the output is faithful — not
just syntactically tidy.

With that context set, the rest of this post is what the roundtrip discipline
surfaced, starting with the headcount split that opened this piece.

## The three blobs

Both platforms carve sandbox bytecode out of the kernel the same way. The
`Sandbox.kext` initializer panics if a collection fails to parse, and the
panic strings make excellent landmarks:

```c
"failed to initialize builtin collection: %d" @%s:%d
"failed to initialize autobox collection: %d" @%s:%d
"failed to initialize platform sandbox: %d" @%s:%d
```

Three strings, three blobs, both platforms. `ipsw` finds the basic block
that references each panic, emulates backwards to the `_collection_init`
arguments, and reads the `(addr, size)` pair right out of the registers.

What differs is what's *in* them. The KDK kext for macOS 26.5 has full
symbols, so `_hook_policy_init` lays it out plainly:

```c
collection_init(&autobox_collection, "autobox collection",
                &autobox_data, 2527, autobox_register);
// ...
collection_init(&builtin_collection, "builtin collection",
                &collection_data, 14947, builtin_register);
// ...
profile_init(&platform_profile, &platform_profile_data, 108656);
```

| Blob | macOS | iOS |
|---|---|---|
| Builtin collection | 14,947 bytes / 14 profiles | ~5 MB / 287 profiles |
| Autobox collection | 2,527 bytes / 3 profiles | similar |
| Platform profile | 108,656 bytes / 1 profile | similar |

The autobox collection (`autobox-tests-allow`, `autobox-tests-deny`,
`pbdevtool`) and the platform profile (the catch-all that backs *every*
process before its real profile attaches) are roughly the same size on both
OSes. The builtin collection is where everything diverges.

## What's missing on macOS isn't missing — it's late-bound

The KDK kext's symbol table holds names that don't exist anywhere in an iOS
kernelcache:

```
_syscall_profile_registration
_registered_profile_list
_registered_profile_list_RB_INSERT
_registered_profile_list_RB_REMOVE
_registered_profile_list_RB_NEXT
_registered_profile_count
_registered_profile_lock
__WAITING_ON_APPROVAL_FROM_SANDBOXD__
```

A red-black tree, an atomic counter, a reader-writer lock. All in
`__DATA.__bss` — runtime mutable. And a syscall handler to feed it.

Decompiling `_syscall_profile_registration` (in `registered.c`, judging by
the panic strings) gives the full picture:

```c
__int64 syscall_profile_registration(AppleMobileFileIntegrity *amfi,
                                     user_addr_t uargs, ...) {
    // Gate: only one entitlement opens this door.
    if (!AMFIEntitlementGetBool(amfi,
            "com.apple.private.security.register-profile", &has_ent)
        || !has_ent) {
        return EPERM;
    }

    // 32-byte argument struct from userspace.
    struct { user_addr_t profile_data; size_t profile_size;
             user_addr_t name_out;     user_addr_t name_size_out; } args;
    copyin(uargs, &args, 0x20);

    if (args.profile_data == NULL) {
        // Unregister path — see below.
    }

    // Register path:
    if (args.profile_size > 0x80000)            // 512 KB cap
        return EINVAL;

    void *kbuf = smalloc_data(args.profile_size);
    copyin(args.profile_data, kbuf, args.profile_size);

    // Parse compiled bytecode in-kernel. Same parser the builtin
    // collection uses — this is NOT source compilation.
    profile *p;
    int rc = profile_create(&p, &name_buf, &kbuf, args.profile_size);
    if (rc) return rc;

    // Mark as runtime-registered.
    *(uint8_t *)(p->collection + 14) = 1;

    if (atomic_fetch_add(&registered_profile_count, 1) == -1)
        panic("registered profile count overflow");

    // Profiles with message filters need a policy ID slot.
    if (*(uint16_t *)(p + 68) & 0x4000) {       // SbTypeHasMessageFilters
        rc = policy_id_reserve(p);
        if (rc) return rc;
    }

    // Generate a name. Three retry attempts on collision.
    for (int tries = 3; tries > 0; tries--) {
        uuid_t u;
        uuid_generate_random(u);
        // Format: "uuid:" + 36-char UUID + NUL = 42 bytes
        memcpy(p->name, "uuid:", 5);
        uuid_unparse(u, p->name + 5);

        profile_retain_persistent(p);
        lck_rw_lock_exclusive(&registered_profile_lock);
        profile *collision = registered_profile_list_RB_INSERT(
                                &registered_profile_list, p);
        lck_rw_unlock_exclusive(&registered_profile_lock);

        if (!collision) {
            // Tell userspace what name we picked.
            size_t namelen = 42;
            copyout(&namelen, args.name_size_out, 8);
            copyoutstr(p->name, args.name_out, 42, &done);
            os_log("registered profile '%s'", p->name);
            return 0;
        }
    }
    return EEXIST;
}
```

A few things stand out:

- **It's bytecode in, not SBPL source.** `profile_create()` is the same
  in-kernel parser that walks `_collection_data` at boot. Userspace
  pre-compiles.
- **The name is kernel-generated.** Userspace doesn't say "register this as
  `com.apple.foo`" — it gets back `uuid:550e8400-e29b-41d4-a716-...`. The
  binding from human-readable name to UUID happens in userspace.
- **It checks our `SbTypeHasMessageFilters` bit.** The `& 0x4000` at offset
  68 is the same flags field `ipsw sb dec` parses out of every profile
  header. Profiles with mach message filtering need a kernel policy slot.
- **The unregister path is the same syscall** with `profile_data=NULL`. Pass
  a name to remove one; pass nothing to wipe the whole tree
  (`"unregistered all runtime profiles"`).

## Who holds the key?

`com.apple.private.security.register-profile` is a needle in a haystack of
several thousand entitled binaries. Scanning `/usr/libexec/` finds exactly
one holder:

```
$ for f in /usr/libexec/*; do
    codesign -d --entitlements - "$f" 2>/dev/null \
      | grep -q register-profile && echo "$f"
  done
/usr/libexec/cryptexd
```

Not `sandboxd`. **`cryptexd`** — the daemon that mounts Apple's signed,
read-only cryptex volumes (the OS cryptex, the App cryptex, the ExclaveOS
cryptex). And `cryptexd` links libsandbox:

```
$ otool -L /usr/libexec/cryptexd | grep sandbox
        /usr/lib/libsandbox.1.dylib

$ nm /usr/libexec/cryptexd | grep sandbox
                 U _sandbox_register_profile
                 U _sandbox_free_profile
0000000100033941 t +[SandboxManager getManager]
0000000100033a49 t -[SandboxManager sandboxHandles]
```

The cstrings tell the rest: `cryptexd` references
`/System/Library/Sandbox/Profiles/` and a per-cryptex template
`cryptex-session-%s.sb`. That directory holds 510 `.sb` source files (plus
59 more in `/usr/share/sandbox/`) — all on the Signed System Volume,
sealed and immutable.

## The full chain

Putting it together, macOS sandbox initialization is a two-phase boot:

```
┌─ kernel boot ──────────────────────────────────────────────────────┐
│  hook_policy_init()                                                │
│    collection_init(&builtin_collection,  ...,  14947 bytes)  ── 14 │
│    collection_init(&autobox_collection,  ...,   2527 bytes)  ──  3 │
│    profile_init   (&platform_profile,    ..., 108656 bytes)  ──  1 │
│    lck_rw_init    (&registered_profile_lock, ...)                  │
│    registered_profile_list = {}                                    │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─ early userspace ──────────────────────────────────────────────────┐
│  cryptexd starts                                                   │
│    (sandboxed by the BUILTIN com.apple.sandboxd profile? no —      │
│     by something already in the 14, or by platform_profile)        │
│                                                                    │
│  for each /System/Library/Sandbox/Profiles/*.sb:                   │
│    bytecode = sandbox_compile_file(path)        ── libsandbox      │
│    handle   = sandbox_register_profile(bytecode)                   │
│                 └─▶ __mac_syscall("Sandbox", ..., args)            │
│                       └─▶ syscall_profile_registration()           │
│                             └─▶ RB_INSERT(&registered_profile_list)│
│    [SandboxManager sandboxHandles] += handle                       │
└────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─ steady state ─────────────────────────────────────────────────────┐
│  Profile lookup checks BOTH:                                       │
│    builtin_collection    (14 entries, __TEXT.__const, immutable)   │
│    registered_profile_list (~510 entries, __DATA.__bss, RB-tree)   │
└────────────────────────────────────────────────────────────────────┘
```

iOS skips phase two entirely. Every profile that will ever exist is in the
builtin collection at link time. Closed system, fixed app set, no need for
the machinery.

## Why split?

The cryptex angle is the tell. Rapid Security Response updates ship as
cryptex deltas — Apple can push a new OS cryptex without shipping a new
kernelcache, without a reboot in some cases. If sandbox profiles were
welded into the kernel like on iOS, fixing a profile bug would mean a full
OS update.

With the runtime path:

| | iOS | macOS |
|---|---|---|
| Profile delivery | Pre-compiled into kernelcache | `.sb` source on SSV |
| Update granularity | New kernelcache | Cryptex update (RSR) |
| Boot cost | Zero (mmap the blob) | Compile ~510 profiles |
| Flexibility | None | Hot-swap a profile via cryptex |

The 14 builtin profiles are the irreducible bootstrap set — the things that
must be sandboxed *before* `cryptexd` itself can run. Look at the list:
`sandboxd` (the userspace half of the sandbox), `endpointsecurityd`
(Endpoint Security Framework), `oahd` (Rosetta), `opendirectoryd`,
`sshd`. All in the critical path before cryptexes mount. Plus the five
generic templates (`no-internet`, `no-network`, `no-write`,
`no-write-except-temporary`, `pure-computation`) that any process can grab
via `sandbox_init()` without involving the registration machinery.

## Two more rabbit holes

The KDK kext has a couple more late-binding mechanisms worth a footnote:

**Bastion profiles.** A separate syscall, `_syscall_bastion_profile_
registration` in `bastion.c`, with its own lock (`_bastion_profile_lock`)
and global pointer (`bastion_globals`). The init code is paranoid:

```c
void *p = IOMallocTypeImpl(&bastion_init_kalloc_type_view);
*p = NULL;
if (!atomic_compare_exchange_strong(&bastion_globals, &(void*){0}, p))
    panic("expected NULL for `bastion_pointers`");
```

This is the DriverKit / System Extensions path — userspace drivers running
in their own sandbox, registered separately from the main RB-tree.

**Ephemeral profiles.** `_ephemeral_profile_list`, `_ephemeral_profile_
count`, `_ephemeral_profile_memory`, `_lookup_ephemeral_profile_locked`.
These are the profiles created by direct `sandbox_init()` calls — a process
compiles SBPL on the fly, applies it to itself, and the profile evaporates
when the process dies. No registration, no persistence.

Neither of these exists on iOS either.

## What this means for `ipsw sb`

The 14+3+1 we extract from macOS kernelcaches is **complete** — there is no
fourth blob, no missing collection type. The other ~510 profiles never
touch the kernelcache.

To analyze the full macOS sandbox surface, compile each on-disk `.sb`
through `libsandbox` and feed the resulting bytecode to the standalone
profile decompiler:

```bash
# Compile a single profile (uses local libsandbox).
# -o is the output DIRECTORY; the compiled blob lands at profile.bin inside it.
$ ipsw sb cmpl /System/Library/Sandbox/Profiles/com.apple.cfprefsd.sb \
    -o /tmp/cfprefsd

# Decompile it back (point --input at the blob, not the directory)
$ ipsw sb dec --type profile -i /tmp/cfprefsd/profile.bin \
    --operations <(ipsw sb opts kernelcache.release.Mac17,6) \
    --darwin-version 25.5
```

The compiled bytecode matches what `cryptexd` would push into the kernel —
same `sandbox_compile_*` API, same wire format. The roundtrip from `.sb`
source → compiled bytecode → decompiled SBPL → recompile converges in
2-4 rounds for everything in `/usr/share/sandbox/`.

<!-- TODO: section on profile bytecode format itself -->
<!-- TODO: section on the SBPL → bytecode compilation pipeline -->
<!-- TODO: section on operation graph + filter trees -->
<!-- TODO: comparison: a single profile (com.apple.WebKit.WebContent?) on
     both platforms — does iOS-builtin == macOS-on-disk-compiled? -->
