---
description: All the MANY ways you can parse a kernelcache.
---

# Parse kernelcache

### **kernel version**

Dump kernelcache version

```bash
❯ ipsw kernel version kernelcache.release.iPhone14,2
"Darwin Kernel Version 21.5.0: Mon Mar 28 22:30:10 PDT 2022; root:xnu-8020.120.43.112.1~1/RELEASE_ARM64_T8110"
"Apple LLVM 13.1.6 (clang-1316.0.21.3) [+internal-os, ptrauth-isa=deployment-target-based]"
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

### **kernel dec**

Decompress a previously extracted **kernelcache**

```bash
❯ ipsw kernel dec kernelcache.release.iphone11
```

:::info
This only works when you have pull them directly out of the IPSW zip as a im4p file *(you should just use `ipsw extract --kernel IPSW` instead)*
:::

### **kernel extract**

Extract KEXT(s) from kernelcache

```bash
❯ ipsw kernel extract kernelcache.release.iPhone15,2 sandbox
   • Created sandbox
```

Dump them all

```bash
❯ ipsw kernel extract kernelcache.release.iPhone15,2 --all --output /tmp/KEXTs
   • Extracting all KEXTs...
      • Created /tmp/KEXTs/com.apple.kernel
      • Created /tmp/KEXTs/com.apple.AGXFirmwareKextG15P_A0RTBuddy
      • Created /tmp/KEXTs/com.apple.AGXFirmwareKextRTBuddy64
      • Created /tmp/KEXTs/com.apple.AGXG15P_A0
      • Created /tmp/KEXTs/com.apple.driver.AOPTouchKext
      • Created /tmp/KEXTs/com.apple.driver.ASIOKit
      • Created /tmp/KEXTs/com.apple.AUC
      • Created /tmp/KEXTs/com.apple.driver.AppleA7IOP
      • Created /tmp/KEXTs/com.apple.driver.AppleALSColorSensor
      • Created /tmp/KEXTs/com.apple.driver.AppleAOPAudio
      • Created /tmp/KEXTs/com.apple.driver.AppleAOPVoiceTrigger
      • Created /tmp/KEXTs/com.apple.iokit.AppleARMIISAudio
      • Created /tmp/KEXTs/com.apple.driver.AppleARMPMU
      • Created /tmp/KEXTs/com.apple.driver.AppleARMPlatform
      • Created /tmp/KEXTs/com.apple.driver.AppleARMWatchdogTimer
      <SNIP>
```

:::info
This only works on the modern `MH_FILESET` kernelcaches and is the same thing as `ipsw macho info KERNELCACHE --fileset-entry "com.apple.security.sandbox" --extract-fileset-entry`
:::

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

<!-- ### **kernel diff**

🚧 **[WIP]** 🚧

I am playing with the idea of `diffing` kernelcaches by creating directory structures of Apple's src from assert strings.

Then you could use `git diff` or something to get a quick **high** level view of what Apple has changed by seeing new files being added or removed as well as seeing the line numbers of the assert strings move around.

```bash
❯ ipsw kernel diff kernelcache.release.iphone11
```

You can see an example of what this outputs [HERE](https://github.com/blacktop/ipsw/tree/master/pkg/kernelcache/diff/Library/Caches/com.apple.xbs/Sources) -->

### **kernel symbolsets**

Dump kernel symbolsets

```bash
❯ ipsw kernel symbolsets 20D47__iPhone15,2/kernelcache.release.iPhone15,2
```
```md
Symbol Sets
===========

com.apple.kpi.bsd: (22.3.0)
---------------------------
_VNOP_BWRITE
_VNOP_FSYNC
_VNOP_IOCTL
_VNOP_READ
_VNOP_STRATEGY
_VNOP_WRITE
_advisory_read
_advisory_read_ext
_bcd2bin_data
_bdevsw_add
_bdevsw_isfree
_bdevsw_remove
<SNIP>
```

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

#### Dump as JSON

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

#### Dump a single `type`

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

Diff two versions of the same struct

```bash
❯ ipsw kernel ctfdump --diff task \
    /Library/Developer/KDKs/KDK_13.0_22A5352e.kdk/System/Library/Kernels/kernel.development.t6000 \
    /Library/Developer/KDKs/KDK_13.1_22C65.kdk/System/Library/Kernels/kernel.development.t6000
   • Differences found
```
```cpp
❌ removed:
    task_control_port_options_t                  task_control_port_options;          // off=0x620
```

### **kernel dwarf**

#### 🚧 Dump DWARF debug information

Dump the task struct *(and pretty print with clang-format)*

```bash
❯ ipsw kernel dwarf --type task \
    KDK_13.1_22C65.kdk/**/kernel.development.t6000.dSYM/**/kernel.development.t6000 \
        | clang-format -style='{AlignConsecutiveDeclarations: true}' --assume-filename task.h
```
```cpp
struct task {
  lck_mtx_t         lock;                                             // @ 0x0
  os_refcnt_t       ref_count;                                        // @ 0x10
  struct os_refgrp *ref_group;                                        // @ 0x20
  lck_spin_t        ref_group_lock;                                   // @ 0x28
  _Bool             active;                                           // @ 0x38
  _Bool             ipc_active;                                       // @ 0x39
  _Bool             halting;                                          // @ 0x3a
  _Bool             message_app_suspended;                            // @ 0x3b
  uint32_t          vtimers;                                          // @ 0x3c
  uint32_t          loadTag;                                          // @ 0x40
  uint64_t          task_uniqueid;                                    // @ 0x48
  __ptrauth(DA, true, 5ef8) map;                                      // @ 0x50
  queue_chain_t              tasks;                                   // @ 0x58
  struct task_watchports    *watchports;                              // @ 0x68
  turnstile_inheritor_t      returnwait_inheritor;                    // @ 0x70
  sched_group_t              sched_group;                             // @ 0x78
  queue_head_t               threads;                                 // @ 0x80
  struct restartable_ranges *t_rr_ranges;                             // @ 0x90
  processor_set_t            pset_hint;                               // @ 0x98
  struct affinity_space     *affinity_space;                          // @ 0xa0
  int                        thread_count;                            // @ 0xa8
  uint32_t                   active_thread_count;                     // @ 0xac
  int                        suspend_count;                           // @ 0xb0
  integer_t                  user_stop_count;                         // @ 0xb4
  integer_t                  legacy_stop_count;                       // @ 0xb8
  int16_t                    priority;                                // @ 0xbc
  int16_t                    max_priority;                            // @ 0xbe
  integer_t                  importance;                              // @ 0xc0
  uint64_t                   total_runnable_time;                     // @ 0xc8
  struct recount_task        tk_recount;                              // @ 0xd0
  lck_mtx_t                  itk_lock_data;                           // @ 0xe0
  __ptrauth(DA, true, 68c5) itk_task_ports[4];                        // @ 0xf0
  __ptrauth(DA, true, 4447) itk_settable_self;                        // @ 0x110
  __ptrauth(DA, true, 58ef) itk_self;                                 // @ 0x118
  struct exception_action exc_actions[14];                            // @ 0x120
  __ptrauth(DA, true, bb51) itk_host;                                 // @ 0x2e0
  __ptrauth(DA, true, e868) itk_bootstrap;                            // @ 0x2e8
  __ptrauth(DA, true, b8b1) itk_debug_control;                        // @ 0x2f0
  __ptrauth(DA, true, ba93) itk_task_access;                          // @ 0x2f8
  __ptrauth(DA, true, ecf) itk_resume;                                // @ 0x300
  __ptrauth(DA, true, a454) itk_registered[3];                        // @ 0x308
  __ptrauth(DA, true, ec7b) itk_dyld_notify;                          // @ 0x320
  __ptrauth(DA, true, 46e7) itk_resource_notify;                      // @ 0x328
  __ptrauth(DA, true, 8280) itk_space;                                // @ 0x330
  ledger_t     ledger;                                                // @ 0x338
  queue_head_t semaphore_list;                                        // @ 0x340
  int          semaphores_owned;                                      // @ 0x350
  unsigned int priv_flags;                                            // @ 0x354
  __ptrauth(DA, true, 1d9a) task_debug;                               // @ 0x358
  uint64_t                     rop_pid;                               // @ 0x360
  uint64_t                     jop_pid;                               // @ 0x368
  uint8_t                      disable_user_jop;                      // @ 0x370
  arm64_uexc_region_t          uexc;                                  // @ 0x378
  _Bool                        preserve_x18;                          // @ 0x398
  counter_t                    faults;                                // @ 0x3a0
  counter_t                    pageins;                               // @ 0x3a8
  counter_t                    cow_faults;                            // @ 0x3b0
  counter_t                    messages_sent;                         // @ 0x3b8
  counter_t                    messages_received;                     // @ 0x3c0
  uint32_t                     decompressions;                        // @ 0x3c8
  uint32_t                     syscalls_mach;                         // @ 0x3cc
  uint32_t                     syscalls_unix;                         // @ 0x3d0
  uint32_t                     c_switch;                              // @ 0x3d4
  uint32_t                     p_switch;                              // @ 0x3d8
  uint32_t                     ps_switch;                             // @ 0x3dc
  struct proc_ro              *bsd_info_ro;                           // @ 0x3e0
  kcdata_descriptor_t          corpse_info;                           // @ 0x3e8
  uint64_t                     crashed_thread_id;                     // @ 0x3f0
  queue_chain_t                corpse_tasks;                          // @ 0x3f8
  struct label                *crash_label;                           // @ 0x408
  volatile uint32_t            t_flags;                               // @ 0x410
  uint32_t                     t_procflags;                           // @ 0x414
  mach_vm_address_t            all_image_info_addr;                   // @ 0x418
  mach_vm_size_t               all_image_info_size;                   // @ 0x420
  uint32_t                     t_kpc;                                 // @ 0x428
  _Bool                        pidsuspended;                          // @ 0x42c
  _Bool                        frozen;                                // @ 0x42d
  _Bool                        changing_freeze_state;                 // @ 0x42e
  _Bool                        is_large_corpse;                       // @ 0x42f
  uint16_t                     policy_ru_cpu : 4 @8576;               // @ 0x0
  uint16_t                     policy_ru_cpu_ext : 4 @8580;           // @ 0x0
  uint16_t                     applied_ru_cpu : 4 @8584;              // @ 0x0
  uint16_t                     applied_ru_cpu_ext : 4 @8588;          // @ 0x0
  uint8_t                      rusage_cpu_flags;                      // @ 0x432
  uint8_t                      rusage_cpu_percentage;                 // @ 0x433
  uint8_t                      rusage_cpu_perthr_percentage;          // @ 0x434
  int8_t                       suspends_outstanding;                  // @ 0x435
  uint8_t                      t_returnwaitflags;                     // @ 0x436
  _Bool                        shared_region_auth_remapped;           // @ 0x437
  char                        *shared_region_id;                      // @ 0x438
  struct vm_shared_region     *shared_region;                         // @ 0x440
  uint64_t                     rusage_cpu_interval;                   // @ 0x448
  uint64_t                     rusage_cpu_perthr_interval;            // @ 0x450
  uint64_t                     rusage_cpu_deadline;                   // @ 0x458
  thread_call_t                rusage_cpu_callt;                      // @ 0x460
  queue_head_t                 task_watchers;                         // @ 0x468
  int                          num_taskwatchers;                      // @ 0x478
  int                          watchapplying;                         // @ 0x47c
  struct bank_task            *bank_context;                          // @ 0x480
  struct ipc_importance_task  *task_imp_base;                         // @ 0x488
  vm_extmod_statistics_data_t  extmod_statistics;                     // @ 0x490
  struct task_requested_policy requested_policy;                      // @ 0x4c0
  struct task_effective_policy effective_policy;                      // @ 0x4c8
  uint32_t                     low_mem_notified_warn : 1 @9856;       // @ 0x0
  uint32_t                     low_mem_notified_critical : 1 @9857;   // @ 0x0
  uint32_t                     purged_memory_warn : 1 @9858;          // @ 0x0
  uint32_t                     purged_memory_critical : 1 @9859;      // @ 0x0
  uint32_t                     low_mem_privileged_listener : 1 @9860; // @ 0x0
  uint32_t                     mem_notify_reserved : 27 @9861;        // @ 0x0
  uint32_t                     memlimit_is_active : 1 @9888;          // @ 0x0
  uint32_t                     memlimit_is_fatal : 1 @9889;           // @ 0x0
  uint32_t                     memlimit_active_exc_resource : 1 @9890;  // @ 0x0
  uint32_t                    memlimit_inactive_exc_resource : 1 @9891; // @ 0x0
  uint32_t                    memlimit_attrs_reserved : 28 @9892;       // @ 0x0
  io_stat_info_t              task_io_stats;                         // @ 0x4d8
  struct task_writes_counters task_writes_counters_internal;         // @ 0x4e0
  struct task_writes_counters task_writes_counters_external;         // @ 0x500
  struct _cpu_time_qos_stats  cpu_time_eqos_stats;                   // @ 0x520
  struct _cpu_time_qos_stats  cpu_time_rqos_stats;                   // @ 0x558
  uint32_t                    task_timer_wakeups_bin_1;              // @ 0x590
  uint32_t                    task_timer_wakeups_bin_2;              // @ 0x594
  uint64_t                    task_gpu_ns;                           // @ 0x598
  uint8_t                     task_can_transfer_memory_ownership;    // @ 0x5a0
  uint8_t                     task_no_footprint_for_debug;           // @ 0x5a1
  uint8_t                     task_objects_disowning;                // @ 0x5a2
  uint8_t                     task_objects_disowned;                 // @ 0x5a3
  int                         task_volatile_objects;                 // @ 0x5a4
  int                         task_nonvolatile_objects;              // @ 0x5a8
  int                         task_owned_objects;                    // @ 0x5ac
  queue_head_t                task_objq;                             // @ 0x5b0
  lck_mtx_t                   task_objq_lock;                        // @ 0x5c0
  unsigned int                task_thread_limit : 16 @11904;         // @ 0x0
  unsigned int                task_legacy_footprint : 1 @11920;      // @ 0x0
  unsigned int                task_extra_footprint_limit : 1 @11921; // @ 0x0
  unsigned int  task_ios13extended_footprint_limit : 1 @11922;       // @ 0x0
  unsigned int  task_region_footprint : 1 @11923;                    // @ 0x0
  unsigned int  task_has_crossed_thread_limit : 1 @11924;            // @ 0x0
  unsigned int  task_rr_in_flight : 1 @11925;                        // @ 0x0
  uint32_t      exec_token;                                          // @ 0x5d4
  coalition_t   coalition[2];                                        // @ 0x5d8
  queue_chain_t task_coalition[2];                                   // @ 0x5e8
  uint64_t      dispatchqueue_offset;                                // @ 0x608
  boolean_t     task_unnested;                                       // @ 0x610
  int           task_disconnected_count;                             // @ 0x614
  __ptrauth(DA, true, 1f57) hv_task_target;                          // @ 0x618
  task_exc_guard_behavior_t          task_exc_guard;                 // @ 0x620
  mach_vm_address_t                  mach_header_vm_address;         // @ 0x628
  queue_head_t                       io_user_clients;                // @ 0x630
  boolean_t                          donates_own_pages;              // @ 0x640
  uint32_t                           task_shared_region_slide;       // @ 0x644
  uint64_t                           task_fs_metadata_writes;        // @ 0x648
  uuid_t                             task_shared_region_uuid;        // @ 0x650
  uint64_t                           memstat_dirty_start;            // @ 0x660
  vmobject_list_output_t             corpse_vmobject_list;           // @ 0x668
  uint64_t                           corpse_vmobject_list_size;      // @ 0x670
  vm_deferred_reclamation_metadata_t deferred_reclamation_metadata;  // @ 0x678
}
```

Diff two versions of a struct

```bash
❯ ipsw kernel dwarf --diff --type task \
    KDK_13.0_22A5352e.kdk/**/kernel.development.t6000 \
    KDK_13.1_22C65.kdk/**/kernel.development.t6000
   • Differences found
```
```cpp
❌ removed:
    task_control_port_options_t task_control_port_options;	// @ 0xc4
```

Diff **ALL** structs

```bash
❯ ipsw kernel dwarf --diff
? Which KDKs would you like to diff (select 2): /Library/Developer/KDKs/KDK_14.4_23E5180j.kdk, /Library/Developer/KDKs/KDK_14.4_23E5191e.kdk
? Choose a kernel type to diff: kernel.release.t6030
   • Diffing all structs
```