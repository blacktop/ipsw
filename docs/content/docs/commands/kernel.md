---
title: "kernel"
date: 2020-01-26T09:17:30-05:00
draft: false
weight: 10
summary: Parse kernelcache.
---

- [**kernel --help**](#kernel---help)
- [**kernel version**](#kernel-version)
- [**kernel extract**](#kernel-extract)
- [**kernel dec**](#kernel-dec)
- [**kernel kexts**](#kernel-kexts)
- [**kernel sbopts**](#kernel-sbopts)
- [**kernel diff**](#kernel-diff)
- [**kernel ctfdump**](#kernel-ctfdump)

---

## **kernel --help**

Help for `kernel` cmd

```bash
❯ ipsw kernel --help

Parse kernelcache

Usage:
  ipsw kernel [flags]
  ipsw kernel [command]

Available Commands:
  ctfdump     Dump CTF info
  dec         Decompress a kernelcache
  extract     Extract and decompress a kernelcache from IPSW
  kexts       List kernel extentions
  sbopts      List kernel sandbox operations
  symbolsets  Dump kernel symbolsets

Flags:
  -h, --help   help for kernel

Global Flags:
      --config string   config file (default is $HOME/.ipsw.yaml)
  -V, --verbose         verbose output

Use "ipsw kernel [command] --help" for more information about a command.
```

### **kernel version**

Dump kernelcache version

```bash
❯ ipsw kernel version kernelcache.release.iPhone14,2
0xfffffff00703e0ca: "Darwin Kernel Version 21.5.0: Mon Mar 28 22:30:10 PDT 2022; root:xnu-8020.120.43.112.1~1/RELEASE_ARM64_T8110"
0xfffffff00703e169: "Apple LLVM 13.1.6 (clang-1316.0.21.3) [+internal-os, ptrauth-isa=deployment-target-based]"
```

Dump as JSON

```
❯ ipsw kernel version kernelcache.release.iPhone14,2 --json | jq .
```

```json
{
  "kernel": {
    "darwin": "21.5.0",
    "date": "2022-03-28T22:30:10Z",
    "xnu": "8020.120.43.112.1~1",
    "type": "RELEASE",
    "arch": "ARM64",
    "cpu": "T8110"
  },
  "llvm": {
    "version": "13.1.6",
    "clang": "1316.0.21.3",
    "flags": ["+internal-os", "ptrauth-isa=deployment-target-based"]
  }
}
```

### **kernel extract**

Extract and decompress a kernelcache from IPSW

```bash
❯ ipsw kernel extract iPodtouch_7_13.3.1_17D5050a_Restore.ipsw
   • Extracting kernelcaches
   • Extracting Kernelcache from IPSW
      • Parsing Kernelcache IMG4
      • Decompressing Kernelcache
      • Kernelcache is LZFSE compressed
      • Created iPod9,1_N112AP_17D5050a/kernelcache.development
```

### **kernel dec**

Decompress a previously extracted **kernelcache**

```bash
❯ ipsw kernel dec kernelcache.release.iphone11
```

### **kernel kexts**

List all the kernelcache's KEXTs

```bash
❯ ipsw kernel kexts kernelcache.release.iphone12.decompressed

FOUND: 230
com.apple.kpi.mach (19.2.0)
com.apple.kpi.private (19.2.0)
com.apple.kpi.unsupported (19.2.0)
com.apple.kpi.iokit (19.2.0)
com.apple.kpi.libkern (19.2.0)
com.apple.kpi.bsd (19.2.0)
com.apple.iokit.IONetworkingFamily (3.4)
com.apple.iokit.IOTimeSyncFamily (810.1)
com.apple.iokit.IOPCIFamily (2.9)
com.apple.driver.IOACIPCFamily (1)
com.apple.iokit.IOSkywalkFamily (1)
com.apple.driver.AppleIPAppender (1.0)
<SNIP>
```

Diff two kernelcache's KEXTs

```bash
❯ ipsw kernel kexts --diff 18A8395/kernelcache 18E5178a/kernelcache # iOS 14.1 vs. iOS 14.5beta4
   • Differences found
com.apple.AGXFirmwareKextG14PRTBuddy (1)
com.apple.AGXFirmwareKextRTBuddy64 (187.3390.17.2)
com.apple.AGXG14P (187.3390.17.2)
com.apple.AUC (1.0)
<SNIP>
```

### **kernel sbopts**

List kernel sandbox operations

```bash
❯ ipsw kernel sbopts 18A8395/kernelcache # iOS 14.1
```

Diff two kernelcache's sandbox operations

```bash
❯ ipsw kernel sbopts --diff 18A8395/kernelcache 18E5178a/kernelcache # iOS 14.1 vs. iOS 14.5beta4
   • Differences found
+mach-task*
+mach-task-inspect

+mach-task-read

+process-codesigning*
+process-codesigning-blob-get
+process-codesigning-cdhash-get
+process-codesigning-entitlements-blob-get
+process-codesigning-identity-get

+process-codesigning-teamid-get
+process-codesigning-text-offset-get

+socket-option*
+socket-option-get
+socket-option-set

+system-fcntl
```

### **kernel diff**

🚧 **[WIP]** 🚧

I am playing with the idea of `diffing` kernelcaches by creating directory structures of Apple's src from assert strings.

Then you could use `git diff` or something to get a quick **high** level view of what Apple has changed by seeing new files being added or removed as well as seeing the line numbers of the assert strings move around.

```bash
❯ ipsw kernel diff kernelcache.release.iphone11
```

You can see an example of what this outputs [HERE](https://github.com/blacktop/ipsw/tree/master/pkg/kernelcache/diff/Library/Caches/com.apple.xbs/Sources)

### **kernel ctfdump**

#### Dump CTF info

KDK kernelcaches contain CTF - _Compact ANSI-C Type Format_ data which is used by dtrace. It's a data format much like DWARF and contains and absolute treasure trove for peeps REing the kernels (types, globals and func signatures).

```bash
❯ ipsw ctfdump KDK
```

```bash
- CTF Header -----------------------------------------------------------------

Magic        = 0xcff1
Version      = 3
Flags        = 0x1
Parent Label = (anon)
Parent Name  = (anon)
Label Offset = 0
Obj Offset   = 8
Func Offset  = 0x247a
Type Offset  = 0x1acf8
Str Offset   = 0xda4f4
Str Len      = 0x763dc


- Types ----------------------------------------------------------------------

[1] INTEGER short encoding=SIGNED offset=0 bits=16

<2> INTEGER char encoding=SIGNED CHAR offset=0 bits=8

[3] INTEGER unsigned char encoding=CHAR offset=0 bits=8

<4> TYPEDEF u_char refers to 3
<5> POINTER (anon) refers to 2
<6> TYPEDEF caddr_t refers to 5
[7] UNION (anon) (8 bytes)
        rmu_mask type=6 off=0x0
        rmu_leaf type=15 off=0x0

<8> INTEGER int encoding=SIGNED offset=0 bits=32

<9> STRUCT radix_mask (32 bytes)
    rm_bit    type=1  off=0x0
    rm_unused type=2  off=0x10
    rm_flags  type=4  off=0x18
    rm_mklist type=10 off=0x40
    rm_rmu    type=7  off=0x80
    rm_refs   type=8  off=0xc0
<SNIP>

- Data Objects ---------------------------------------------------------------

0xfffffe00072bf0a0: <unknown> AccelerateCrypto_SHA256_compress
0xfffffe00071b4ce8: boot_args * BootArgs
0xfffffe0007dc0b20: cpu_data_entry_t[8] CpuDataEntries
0xfffffe00072a4a58: RealDTEntry DTRootNode
0xfffffe0007dc1dd0: unsigned int DebugContextCount
0xfffffe0007dfd708: <unknown> IOLockGroup
0xfffffe0007dfd6fc: <unknown> IOZeroTvalspec
0xfffffe000700b114: const audit_token_t KERNEL_AUDIT_TOKEN
0xfffffe000700b10c: const security_token_t KERNEL_SECURITY_TOKEN
0xfffffe00071ab838: struct kalloc_heap[1] KHEAP_DATA_BUFFERS
0xfffffe00071ab240: struct kalloc_heap[1] KHEAP_DEFAULT
0xfffffe0007243660: struct kalloc_heap[1] KHEAP_DTRACE
0xfffffe00071abd10: struct kalloc_heap[1] KHEAP_KEXT
0xfffffe00072458a0: struct kalloc_heap[1] KHEAP_VFS_BIO
<SNIP>

- Functions ------------------------------------------------------------------

0xfffffe0007cce944: void Assert();
0xfffffe0007943624: int CURSIG(proc_t);
0xfffffe00074df8c8: void ClearIdlePop();
0xfffffe00073250dc: void Debugger();
0xfffffe00074dd82c: void DebuggerCall();
0xfffffe0007324ebc: kern_return_t DebuggerTrapWithState(debugger_op, const char *, const char *, va_list *, uint64_t, void *, boolean_t, unsigned long);
0xfffffe00073250f0: void DebuggerWithContext();
0xfffffe00074dd608: void DebuggerXCall();
0xfffffe00074dd070: kern_return_t DebuggerXCallEnter(boolean_t);
0xfffffe00074dd554: void DebuggerXCallReturn();
0xfffffe000748eb1c: unsigned int IODefaultCacheBits(addr64_t);
0xfffffe000748ee0c: ppnum_t IOGetLastPageNumber();
0xfffffe000748ee14: void IOGetTime();
0xfffffe000748eb2c: kern_return_t IOMapPages(vm_map_t, mach_vm_address_t, mach_vm_address_t, mach_vm_size_t, unsigned int);
```

### Dump as JSON

```bash
❯ ipsw ctfdump KDK --json
   • Creating ctfdump.json
```

```json
{
    "header": {
        "preamble": {
            "magic": 53233,
            "version": 3,
            "flags": 1
        },
        "obj_offset": 8,
        "func_offset": 9338,
        "type_offset": 109816,
        "str_offset": 894196,
        "str_len": 484316,
        "parent_label": "(anon)",
        "parent_name": "(anon)"
    },
    "types": {
        "1": {
            "id": 1,
            "name": "short",
            "info": {
                "kind": "INTEGER",
                "var_len": 1
            },
            "encoding": {
                "encoding": "SIGNED",
                "bits": 16
            }
        },
        "10": {
            "id": 10,
            "name": "(anon)",
            "info": {
                "kind": "POINTER"
            },
            "reference": "struct radix_mask"
        },
<SNIP>
```

### Dump a single `type`

```bash
❯ ipsw ctfdump KDK/macOS12beta/kernel.development.t8101 task > task.h
```

```bash
❯ cat task.h
```

```cpp
struct task
{                                                                 // (1728 bytes)
    lck_mtx_t lock;                                               // off=0x0
    os_refcnt_t ref_count;                                        // off=0x80
    struct os_refgrp *ref_group;                                  // off=0x100
    lck_spin_t ref_group_lock;                                    // off=0x140
    _Bool active;                                                 // off=0x1c0
    _Bool ipc_active;                                             // off=0x1c8
    _Bool halting;                                                // off=0x1d0
    _Bool message_app_suspended;                                  // off=0x1d8
    uint32_t vtimers;                                             // off=0x1e0
    uint64_t task_uniqueid;                                       // off=0x200
    vm_map_t __ptrauth(DA, true, 5ef8) map;                       // off=0x240
    queue_chain_t tasks;                                          // off=0x280
    struct task_watchports *watchports;                           // off=0x300
    turnstile_inheritor_t returnwait_inheritor;                   // off=0x340
    sched_group_t sched_group;                                    // off=0x380
    queue_head_t threads;                                         // off=0x3c0
    struct restartable_ranges *restartable_ranges;                // off=0x440
    processor_set_t pset_hint;                                    // off=0x480
    struct affinity_space *affinity_space;                        // off=0x4c0
    int thread_count;                                             // off=0x500
    uint32_t active_thread_count;                                 // off=0x520
    int suspend_count;                                            // off=0x540
    integer_t user_stop_count;                                    // off=0x560
    integer_t legacy_stop_count;                                  // off=0x580
    int16_t priority;                                             // off=0x5a0
    int16_t max_priority;                                         // off=0x5b0
    integer_t importance;                                         // off=0x5c0
    security_token_t sec_token;                                   // off=0x5e0
    audit_token_t audit_token;                                    // off=0x620
    uint64_t total_user_time;                                     // off=0x740
    uint64_t total_system_time;                                   // off=0x780
    uint64_t total_ptime;                                         // off=0x7c0
    uint64_t total_runnable_time;                                 // off=0x800
    lck_mtx_t itk_lock_data;                                      // off=0x840
    struct ipc_port *__ptrauth(DA, true, 68c5) itk_task_ports[4]; // off=0x8c0
    struct ipc_port *__ptrauth(DA, true, 4447) itk_settable_self; // off=0x9c0
    struct ipc_port *__ptrauth(DA, true, 58ef) itk_self;          // off=0xa00
    struct exception_action exc_actions[14];                      // off=0xa40
    struct ipc_port *__ptrauth(DA, true, bb51) itk_host;          // off=0x1840
    struct ipc_port *__ptrauth(DA, true, e868) itk_bootstrap;     // off=0x1880
    struct ipc_port *__ptrauth(DA, true, b8b1) itk_debug_control; // off=0x18c0
    struct ipc_port *__ptrauth(DA, true, ba93) itk_task_access;   // off=0x1900
    struct ipc_port *__ptrauth(DA, true, 0ecf) itk_resume;        // off=0x1940
    struct ipc_port *__ptrauth(DA, true, a454) itk_registered[3]; // off=0x1980
    ipc_port_t *__ptrauth(DA, true, ec7b) itk_dyld_notify;        // off=0x1a40
    struct ipc_space *__ptrauth(DA, true, 8280) itk_space;        // off=0x1a80
    ledger_t ledger;                                              // off=0x1ac0
    queue_head_t semaphore_list;                                  // off=0x1b00
    int semaphores_owned;                                         // off=0x1b80
    unsigned int priv_flags;                                      // off=0x1ba0
    void *__ptrauth(DA, true, 1d9a) task_debug;                   // off=0x1bc0
    uint64_t rop_pid;                                             // off=0x1c00
    uint64_t jop_pid;                                             // off=0x1c40
    uint8_t disable_user_jop;                                     // off=0x1c80
    arm64_uexc_region_t uexc;                                     // off=0x1cc0
    counter_t faults;                                             // off=0x1dc0
    integer_t decompressions;                                     // off=0x1e00
    integer_t pageins;                                            // off=0x1e20
    integer_t cow_faults;                                         // off=0x1e40
    integer_t messages_sent;                                      // off=0x1e60
    integer_t messages_received;                                  // off=0x1e80
    integer_t syscalls_mach;                                      // off=0x1ea0
    integer_t syscalls_unix;                                      // off=0x1ec0
    uint32_t c_switch;                                            // off=0x1ee0
    uint32_t p_switch;                                            // off=0x1f00
    uint32_t ps_switch;                                           // off=0x1f20
    void *__ptrauth(DA, true, ce5a) bsd_info;                     // off=0x1f40
    kcdata_descriptor_t corpse_info;                              // off=0x1f80
    uint64_t crashed_thread_id;                                   // off=0x1fc0
    queue_chain_t corpse_tasks;                                   // off=0x2000
    struct label *crash_label;                                    // off=0x2080
    uint8_t *mach_trap_filter_mask;                               // off=0x20c0
    uint8_t *mach_kobj_filter_mask;                               // off=0x2100
    struct vm_shared_region *shared_region;                       // off=0x2140
    char *shared_region_id;                                       // off=0x2180
    _Bool shared_region_auth_remapped;                            // off=0x21c0
    volatile uint32_t t_flags;                                    // off=0x21e0
    uint32_t t_procflags;                                         // off=0x2200
    uint8_t t_returnwaitflags;                                    // off=0x2220
    mach_vm_address_t all_image_info_addr;                        // off=0x2240
    mach_vm_size_t all_image_info_size;                           // off=0x2280
    uint32_t t_kpc;                                               // off=0x22c0
    boolean_t pidsuspended;                                       // off=0x22e0
    boolean_t frozen;                                             // off=0x2300
    boolean_t changing_freeze_state;                              // off=0x2320
    unsigned short policy_ru_cpu;                                 // off=0x2340
    unsigned short policy_ru_cpu_ext;                             // off=0x2344
    unsigned short applied_ru_cpu;                                // off=0x2348
    unsigned short applied_ru_cpu_ext;                            // off=0x234c
    uint8_t rusage_cpu_flags;                                     // off=0x2350
    uint8_t rusage_cpu_percentage;                                // off=0x2358
    uint8_t rusage_cpu_perthr_percentage;                         // off=0x2360
    int8_t suspends_outstanding;                                  // off=0x2368
    uint64_t rusage_cpu_interval;                                 // off=0x2380
    uint64_t rusage_cpu_perthr_interval;                          // off=0x23c0
    uint64_t rusage_cpu_deadline;                                 // off=0x2400
    thread_call_t rusage_cpu_callt;                               // off=0x2440
    queue_head_t task_watchers;                                   // off=0x2480
    int num_taskwatchers;                                         // off=0x2500
    int watchapplying;                                            // off=0x2520
    struct bank_task *bank_context;                               // off=0x2540
    struct ipc_importance_task *task_imp_base;                    // off=0x2580
    vm_extmod_statistics_data_t extmod_statistics;                // off=0x25c0
    struct task_requested_policy requested_policy;                // off=0x2740
    struct task_effective_policy effective_policy;                // off=0x2780
    unsigned int low_mem_notified_warn;                           // off=0x27c0
    unsigned int low_mem_notified_critical;                       // off=0x27c1
    unsigned int purged_memory_warn;                              // off=0x27c2
    unsigned int purged_memory_critical;                          // off=0x27c3
    unsigned int low_mem_privileged_listener;                     // off=0x27c4
    unsigned int mem_notify_reserved;                             // off=0x27c5
    unsigned int memlimit_is_active;                              // off=0x27e0
    unsigned int memlimit_is_fatal;                               // off=0x27e1
    unsigned int memlimit_active_exc_resource;                    // off=0x27e2
    unsigned int memlimit_inactive_exc_resource;                  // off=0x27e3
    unsigned int memlimit_attrs_reserved;                         // off=0x27e4
    io_stat_info_t task_io_stats;                                 // off=0x2800
    struct task_writes_counters task_writes_counters_internal;    // off=0x2840
    struct task_writes_counters task_writes_counters_external;    // off=0x2940
    struct _cpu_time_qos_stats cpu_time_eqos_stats;               // off=0x2a40
    struct _cpu_time_qos_stats cpu_time_rqos_stats;               // off=0x2c00
    uint32_t task_timer_wakeups_bin_1;                            // off=0x2dc0
    uint32_t task_timer_wakeups_bin_2;                            // off=0x2de0
    uint64_t task_gpu_ns;                                         // off=0x2e00
    uint64_t task_energy;                                         // off=0x2e40
    struct mt_task task_monotonic;                                // off=0x2e80
    uint8_t task_can_transfer_memory_ownership;                   // off=0x2f00
    uint8_t task_no_footprint_for_debug;                          // off=0x2f08
    uint8_t task_objects_disowning;                               // off=0x2f10
    uint8_t task_objects_disowned;                                // off=0x2f18
    int task_volatile_objects;                                    // off=0x2f20
    int task_nonvolatile_objects;                                 // off=0x2f40
    int task_owned_objects;                                       // off=0x2f60
    queue_head_t task_objq;                                       // off=0x2f80
    lck_mtx_t task_objq_lock;                                     // off=0x3000
    unsigned int task_thread_limit;                               // off=0x3080
    unsigned int task_legacy_footprint;                           // off=0x3090
    unsigned int task_extra_footprint_limit;                      // off=0x3091
    unsigned int task_ios13extended_footprint_limit;              // off=0x3092
    unsigned int task_region_footprint;                           // off=0x3093
    unsigned int task_has_crossed_thread_limit;                   // off=0x3094
    uint32_t exec_token;                                          // off=0x30a0
    coalition_t coalition[2];                                     // off=0x30c0
    queue_chain_t task_coalition[2];                              // off=0x3140
    uint64_t dispatchqueue_offset;                                // off=0x3240
    boolean_t task_unnested;                                      // off=0x3280
    int task_disconnected_count;                                  // off=0x32a0
    void *__ptrauth(DA, true, 1f57) hv_task_target;               // off=0x32c0
    task_exc_guard_behavior_t task_exc_guard;                     // off=0x3300
    task_control_port_options_t task_control_port_options;        // off=0x3320
    queue_head_t io_user_clients;                                 // off=0x3340
    mach_vm_address_t mach_header_vm_address;                     // off=0x33c0
    uint32_t loadTag;                                             // off=0x3400
    uint64_t task_fs_metadata_writes;                             // off=0x3440
    uint32_t task_shared_region_slide;                            // off=0x3480
    uuid_t task_shared_region_uuid;                               // off=0x34a0
    uint64_t memstat_dirty_start;                                 // off=0x3540
    vmobject_list_output_t corpse_vmobject_list;                  // off=0x3580
    uint64_t corpse_vmobject_list_size;                           // off=0x35c0
};
```
