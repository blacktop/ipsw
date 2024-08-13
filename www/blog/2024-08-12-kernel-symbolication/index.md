---
slug: kernel-symbolication
title: Kernel Symbolication
authors: [blacktop]
tags: [kernel, symbolication]
image: ./kernel-symbolication.webp
hide_table_of_contents: false
draft: true
---

![kernel-symbolicatione](./kernel-symbolication.webp)

## 🔐 Unlocking the Power of Kernelcache Symbolication

In the world of reverse engineering and kernel analysis, being able to **symbolicate** a stripped Apple **kernelcache** is a game-changer. With the latest feature added to `ipsw`, you can now effortlessly symbolicate a kernelcache, even when it’s stripped of symbols. To make it even better, we’ve integrated this functionality directly into IDA Pro via a brand new [plugin](https://github.com/blacktop/symbolicator/tree/main/ida/plugins/README.md), streamlining the entire process for you.

### A Quick Demo: Symbolicating a Kernelcache in IDA Pro

Let’s jump straight into the action. Here’s how you can use the new feature:

1. Install the `ipsw` tool from [GitHub](https://github.com/blacktop/ipsw) if you haven't already.
2. Fetch the latest **kernelcache** you’re interested in:
   ```bash
   ❯ ipsw dl ipsw --build 21E219 --device iPad7,4 --kernel
      • Parsing remote IPSW       build=21E219 device=iPad7,4 signed=false version=17.4
      • Extracting remote kernelcache
         • Created 21E219__iPad7,4/kernelcache.release.iPad7,1_2_3_4
   ```
3. Check how many symbols we have to start with:
   ```bash
   ❯ ipsw macho info kernelcache.release.iPad7,1_2_3_4 | grep LC_SYMTAB

   018: LC_SYMTAB Symbol offset=0x009FE1D0, Num Syms: 6052, String offset=...
   ```
4. Get the **latest** signature files:
   ```bash
   ❯ git clone https://github.com/blacktop/symbolicator.git
   ```
5. Use the new feature to **symbolicate** it:
   ```bash
   ❯ ipsw kernel symbolicate --signatures 'symbolicator/kernel' --json \
                '21E219__iPad7,4/kernelcache.release.iPad7,1_2_3_4'
      • Parsing Signatures       
      • Symbolicating...          kernelcache=kernelcache.release.iPad7,1_2_3_4
      • Found                     bsd_syscall_table=0xfffffff007156bd8
      • Found                     mach_trap_table=0xfffffff00710d448
      • Found                     mig_kern_subsystem table=0xfffffff0071009c8
      • failed to get MIG subsystems error=failed to get MIG subsystems: EOF
      • Analyzing MachO...        name=com.apple.kernel
         • Signature Not Matched     macho=com.apple.kernel symbol=fbt_provide_probe
         • Symbolicated              address=0xfffffff007337338 file=com.apple.kernel symbol=__stack_chk_fail
         • Signature Not Matched     macho=com.apple.kernel symbol=kdp_packet
         • Signature Not Matched     macho=com.apple.kernel symbol=kdp_set_breakpoint_internal
         • Signature Not Matched     macho=com.apple.kernel symbol=kdp_remove_all_breakpoints
         • Signature Not Matched     macho=com.apple.kernel symbol=kdp_unknown
         • Symbolicated              address=0xfffffff00723aebc file=com.apple.kernel symbol=kernel_bootstrap
            • Symbolicated (Caller)     address=0xfffffff00723aebc file=com.apple.kernel symbol=machine_startup
            • Symbolicated (Caller)     address=0xfffffff00723aebc file=com.apple.kernel symbol=arm_init
            • Symbolicated (Caller)     address=0xfffffff00723aebc file=com.apple.kernel symbol=_start_first_cpu
            • Symbolicated (Caller)     address=0xfffffff00723aebc file=com.apple.kernel symbol=_LowResetVectorEnd
         • Symbolicated              address=0xfffffff0071d3b5c file=com.apple.kernel symbol=finalize_kcdata                
         <SNIP>
      • Writing symbols as JSON to 21E219__iPad7,4/kernelcache.release.iPad7,1_2_3_4.symbols.json      
   ```
6. Install the **IDA Pro** [Symbolicate Plugin](https://github.com/blacktop/symbolicator/tree/main/ida/plugins):
   ```bash
   ❯ bash ida/plugins/install.sh
   ```
7. Load the **kernelcache** into **IDA Pro**.
8. Press `Alt + F8` and watch as the new plugin kicks in, transforming the stripped **kernelcache** into a fully symbolicated treasure trove of information.

![IDAPro](https://raw.githubusercontent.com/blacktop/symbolicator/main/ida/docs/ida.png)

:::info GYATT
#### Notice that's 20k *NEW* symbols!!
:::

With this new feature, you can now see the NEW symbols directly in IDA Pro, allowing for deeper analysis and a better understanding of the **kernelcache** you’re working with.

### How It Works

The magic behind this new feature lies in the signatures that are essential for successful symbolication. These signatures are derived from the [Symbolicator](https://github.com/blacktop/symbolicator) repository. Here’s a breakdown of the process:

1. **Signature Extraction:** We use **IDA Pro** to analyze a symbolicated **KDK kernelcache**. Through this process, we extract unique signatures that correspond to various functions and elements within the **kernelcache**.
2. **Integration with `ipsw`:** Once these signatures are extracted, they’re utilized by the `ipsw` tool to map the stripped **kernelcache**. This mapping process effectively restores the symbols, making the previously cryptic **kernelcache** readable and analyzable.
3. **IDA Pro Plugin:** The new IDA Pro [plugin](https://github.com/blacktop/symbolicator/tree/main/ida/plugins/README.md), which accompanies this feature, automatically applies these symbols within your IDA Pro environment. This seamless integration means you can move from a stripped **kernelcache** to a fully symbolicated one in just a few steps.

### Signatures

The [Symbolicator](https://github.com/blacktop/symbolicator) signatures are generated by running a series of *IDAPython* scripts on a fully symbolicated *Kernel Debug Kit* **kernelcache** with DWARF data. Here is the high-level process:

1. Create lists of all the **unique** strings *per* section *(as we can have duplicates in different Mach-O sections)*.
2. Filter these lists of **unique** strings to ONLY those that have a single XREF in the **kernelcache** *(these are `anchor` strings)*.
3. Attempt to find the function call that will use the `anchor` as an argument via *light* emulation by walking ASM instructions, which can get more symbols.
4. Now that we have an `anchor` to a function/symbol in the **kernelcache**, create unique XREF chains from these **symbols** *(essentially back-traces, but only single XREF trace chains)*.

#### Signature Format

A JSON schema file for `ipsw`'s kernel symbol format can be found [here](https://github.com/blacktop/symbolicator/blob/main/schema.json) in the [Symbolicator](https://github.com/blacktop/symbolicator) repository.

Here is an example of [kernel/24/xnu.json](https://github.com/blacktop/symbolicator/blob/main/kernel/24/xnu.json):
```json
{
    "target": "com.apple.kernel",
    "total": 4462,
    "version": {
        "max": "24.0.0",
        "min": "24.0.0"
    },
    "signatures": [
        {
            "args": 1,
            "anchors": [
                {
                    "string": "dtrace: fbt: No return probe for %s, walked to next routine at 0x%016llx\n",
                    "segment": "__TEXT",
                    "section": "__cstring",
                    "caller": "kprintf"
                }
            ],
            "symbol": "fbt_provide_probe",
            "prototype": "",
            "backtrace": []
        },
<SNIP>
```

:::info Notice
- The field `target` is used to limit what file the **signature** will be applied to. This one is for the `kernel` itself; others are for **KEXTs**.  
- The field `total` is used for metrics and debugging how well the **signature** is performing.
- The `version` field allows for **signature** versioning, meaning that there will be a **kernel** signature file for: `iOS 14`, `iOS 15`, `iOS 16`, `iOS 17`, and `iOS 18`.
- The `signatures` field is an array of **symbols** and their **anchors** *(and which section they came from and the `caller` that uses it as an argument)*; there is also `backtrace`, which is an array of strings that represent its XREF chain.
:::

### Why This Matters
Symbolicating a stripped **kernelcache** opens up new possibilities for reverse engineers, security researchers, and developers who need to dig deep into Apple’s kernel internals. With this new feature, you no longer need to struggle with a barebones **kernelcache**. Instead, you can fully unlock its potential, making your analysis more accurate and comprehensive.

### Get Started

Ready to give it a try? Head over to the [`ipsw`](https://github.com/blacktop/ipsw/releases) page to check out the new feature. Don’t forget to explore the [Symbolicator](https://github.com/blacktop/symbolicator) repo as well, where you can learn more about the signature extraction process and how it ties everything together.

By combining these powerful tools, you’re well-equipped to take your kernel analysis to the next level. Happy symbolication!

#### Future Steps and *Help Wanted*

A few ideas I have to improve upon what we have now are:

- Add binary pattern matching to the signature format to allow matching unique sets of opcodes/instructions to identify more symbols.
- Identify static variables in the DATA __const section via strings/byte patterns.
- Implement something similar to the epic [iometa](https://github.com/Siguza/iometa) tool to capture valuable C++ symbols.

🙏 **Help Wanted**

- The hope in creating something like this publicly is to have the community contribute *artisanal* hand-crafted signatures for some of their favorite/important symbols as well as help maintain these and keep them working long into the future.  
- We'd love to also have **plugins** for:
  - Ghidra
  - Binary Ninja