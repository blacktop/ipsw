---
title: "ctfdump"
date: 2021-08-22T23:34:02-06:00
weight: 19
summary: Dump CTF info.
---

### Dump CTF info

KDK kernelcaches contain CTF - _Compact ANSI-C Type Format_ data which is used by dtrace. It's a data format much like DWARF and contains and absolute treasure trove for peeps REing the kernels (types, globals and func signatures).

```bash
$ ipsw ctfdump KDK

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
```

### Dump a single `type`

```bash
$ ipsw ctfdump KDK/macOS12beta/kernel.development.t8101 task > task.h
```

```bash
$ cat task.h
```

```cpp
struct task {                                                                        // (1728 bytes)
    lck_mtx_t                                    lock;                               // off=0x0
    os_refcnt_t                                  ref_count;                          // off=0x80
    struct os_refgrp *                           ref_group;                          // off=0x100
    lck_spin_t                                   ref_group_lock;                     // off=0x140
    _Bool                                        active;                             // off=0x1c0
    _Bool                                        ipc_active;                         // off=0x1c8
    _Bool                                        halting;                            // off=0x1d0
    _Bool                                        message_app_suspended;              // off=0x1d8
    uint32_t                                     vtimers;                            // off=0x1e0
    uint64_t                                     task_uniqueid;                      // off=0x200
    vm_map_t __ptrauth(DA, true, 5ef8)           map;                                // off=0x240
    queue_chain_t                                tasks;                              // off=0x280
    struct task_watchports *                     watchports;                         // off=0x300
    turnstile_inheritor_t                        returnwait_inheritor;               // off=0x340
    sched_group_t                                sched_group;                        // off=0x380
    queue_head_t                                 threads;                            // off=0x3c0
    struct restartable_ranges *                  restartable_ranges;                 // off=0x440
    processor_set_t                              pset_hint;                          // off=0x480
    struct affinity_space *                      affinity_space;                     // off=0x4c0
    int                                          thread_count;                       // off=0x500
    uint32_t                                     active_thread_count;                // off=0x520
    int                                          suspend_count;                      // off=0x540
    integer_t                                    user_stop_count;                    // off=0x560
    integer_t                                    legacy_stop_count;                  // off=0x580
    int16_t                                      priority;                           // off=0x5a0
    int16_t                                      max_priority;                       // off=0x5b0
    integer_t                                    importance;                         // off=0x5c0
    security_token_t                             sec_token;                          // off=0x5e0
    audit_token_t                                audit_token;                        // off=0x620
    uint64_t                                     total_user_time;                    // off=0x740
    uint64_t                                     total_system_time;                  // off=0x780
    uint64_t                                     total_ptime;                        // off=0x7c0
    uint64_t                                     total_runnable_time;                // off=0x800
    lck_mtx_t                                    itk_lock_data;                      // off=0x840
    struct ipc_port * __ptrauth(DA, true, 68c5)  itk_task_ports[4];                  // off=0x8c0
    struct ipc_port * __ptrauth(DA, true, 4447)  itk_settable_self;                  // off=0x9c0
    struct ipc_port * __ptrauth(DA, true, 58ef)  itk_self;                           // off=0xa00
    struct exception_action                      exc_actions[14];                    // off=0xa40
    struct ipc_port * __ptrauth(DA, true, bb51)  itk_host;                           // off=0x1840
    struct ipc_port * __ptrauth(DA, true, e868)  itk_bootstrap;                      // off=0x1880
    struct ipc_port * __ptrauth(DA, true, b8b1)  itk_debug_control;                  // off=0x18c0
    struct ipc_port * __ptrauth(DA, true, ba93)  itk_task_access;                    // off=0x1900
    struct ipc_port * __ptrauth(DA, true, 0ecf)  itk_resume;                         // off=0x1940
    struct ipc_port * __ptrauth(DA, true, a454)  itk_registered[3];                  // off=0x1980
    ipc_port_t * __ptrauth(DA, true, ec7b)       itk_dyld_notify;                    // off=0x1a40
    struct ipc_space * __ptrauth(DA, true, 8280) itk_space;                          // off=0x1a80
    ledger_t                                     ledger;                             // off=0x1ac0
    queue_head_t                                 semaphore_list;                     // off=0x1b00
    int                                          semaphores_owned;                   // off=0x1b80
    unsigned int                                 priv_flags;                         // off=0x1ba0
    void * __ptrauth(DA, true, 1d9a)             task_debug;                         // off=0x1bc0
    uint64_t                                     rop_pid;                            // off=0x1c00
    uint64_t                                     jop_pid;                            // off=0x1c40
    uint8_t                                      disable_user_jop;                   // off=0x1c80
    arm64_uexc_region_t                          uexc;                               // off=0x1cc0
    counter_t                                    faults;                             // off=0x1dc0
    integer_t                                    decompressions;                     // off=0x1e00
    integer_t                                    pageins;                            // off=0x1e20
    integer_t                                    cow_faults;                         // off=0x1e40
    integer_t                                    messages_sent;                      // off=0x1e60
    integer_t                                    messages_received;                  // off=0x1e80
    integer_t                                    syscalls_mach;                      // off=0x1ea0
    integer_t                                    syscalls_unix;                      // off=0x1ec0
    uint32_t                                     c_switch;                           // off=0x1ee0
    uint32_t                                     p_switch;                           // off=0x1f00
    uint32_t                                     ps_switch;                          // off=0x1f20
    void * __ptrauth(DA, true, ce5a)             bsd_info;                           // off=0x1f40
    kcdata_descriptor_t                          corpse_info;                        // off=0x1f80
    uint64_t                                     crashed_thread_id;                  // off=0x1fc0
    queue_chain_t                                corpse_tasks;                       // off=0x2000
    struct label *                               crash_label;                        // off=0x2080
    uint8_t *                                    mach_trap_filter_mask;              // off=0x20c0
    uint8_t *                                    mach_kobj_filter_mask;              // off=0x2100
    struct vm_shared_region *                    shared_region;                      // off=0x2140
    char *                                       shared_region_id;                   // off=0x2180
    _Bool                                        shared_region_auth_remapped;        // off=0x21c0
    volatile uint32_t                            t_flags;                            // off=0x21e0
    uint32_t                                     t_procflags;                        // off=0x2200
    uint8_t                                      t_returnwaitflags;                  // off=0x2220
    mach_vm_address_t                            all_image_info_addr;                // off=0x2240
    mach_vm_size_t                               all_image_info_size;                // off=0x2280
    uint32_t                                     t_kpc;                              // off=0x22c0
    boolean_t                                    pidsuspended;                       // off=0x22e0
    boolean_t                                    frozen;                             // off=0x2300
    boolean_t                                    changing_freeze_state;              // off=0x2320
    unsigned short                               policy_ru_cpu;                      // off=0x2340
    unsigned short                               policy_ru_cpu_ext;                  // off=0x2344
    unsigned short                               applied_ru_cpu;                     // off=0x2348
    unsigned short                               applied_ru_cpu_ext;                 // off=0x234c
    uint8_t                                      rusage_cpu_flags;                   // off=0x2350
    uint8_t                                      rusage_cpu_percentage;              // off=0x2358
    uint8_t                                      rusage_cpu_perthr_percentage;       // off=0x2360
    int8_t                                       suspends_outstanding;               // off=0x2368
    uint64_t                                     rusage_cpu_interval;                // off=0x2380
    uint64_t                                     rusage_cpu_perthr_interval;         // off=0x23c0
    uint64_t                                     rusage_cpu_deadline;                // off=0x2400
    thread_call_t                                rusage_cpu_callt;                   // off=0x2440
    queue_head_t                                 task_watchers;                      // off=0x2480
    int                                          num_taskwatchers;                   // off=0x2500
    int                                          watchapplying;                      // off=0x2520
    struct bank_task *                           bank_context;                       // off=0x2540
    struct ipc_importance_task *                 task_imp_base;                      // off=0x2580
    vm_extmod_statistics_data_t                  extmod_statistics;                  // off=0x25c0
    struct task_requested_policy                 requested_policy;                   // off=0x2740
    struct task_effective_policy                 effective_policy;                   // off=0x2780
    unsigned int                                 low_mem_notified_warn;              // off=0x27c0
    unsigned int                                 low_mem_notified_critical;          // off=0x27c1
    unsigned int                                 purged_memory_warn;                 // off=0x27c2
    unsigned int                                 purged_memory_critical;             // off=0x27c3
    unsigned int                                 low_mem_privileged_listener;        // off=0x27c4
    unsigned int                                 mem_notify_reserved;                // off=0x27c5
    unsigned int                                 memlimit_is_active;                 // off=0x27e0
    unsigned int                                 memlimit_is_fatal;                  // off=0x27e1
    unsigned int                                 memlimit_active_exc_resource;       // off=0x27e2
    unsigned int                                 memlimit_inactive_exc_resource;     // off=0x27e3
    unsigned int                                 memlimit_attrs_reserved;            // off=0x27e4
    io_stat_info_t                               task_io_stats;                      // off=0x2800
    struct task_writes_counters                  task_writes_counters_internal;      // off=0x2840
    struct task_writes_counters                  task_writes_counters_external;      // off=0x2940
    struct _cpu_time_qos_stats                   cpu_time_eqos_stats;                // off=0x2a40
    struct _cpu_time_qos_stats                   cpu_time_rqos_stats;                // off=0x2c00
    uint32_t                                     task_timer_wakeups_bin_1;           // off=0x2dc0
    uint32_t                                     task_timer_wakeups_bin_2;           // off=0x2de0
    uint64_t                                     task_gpu_ns;                        // off=0x2e00
    uint64_t                                     task_energy;                        // off=0x2e40
    struct mt_task                               task_monotonic;                     // off=0x2e80
    uint8_t                                      task_can_transfer_memory_ownership; // off=0x2f00
    uint8_t                                      task_no_footprint_for_debug;        // off=0x2f08
    uint8_t                                      task_objects_disowning;             // off=0x2f10
    uint8_t                                      task_objects_disowned;              // off=0x2f18
    int                                          task_volatile_objects;              // off=0x2f20
    int                                          task_nonvolatile_objects;           // off=0x2f40
    int                                          task_owned_objects;                 // off=0x2f60
    queue_head_t                                 task_objq;                          // off=0x2f80
    lck_mtx_t                                    task_objq_lock;                     // off=0x3000
    unsigned int                                 task_thread_limit;                  // off=0x3080
    unsigned int                                 task_legacy_footprint;              // off=0x3090
    unsigned int                                 task_extra_footprint_limit;         // off=0x3091
    unsigned int                                 task_ios13extended_footprint_limit; // off=0x3092
    unsigned int                                 task_region_footprint;              // off=0x3093
    unsigned int                                 task_has_crossed_thread_limit;      // off=0x3094
    uint32_t                                     exec_token;                         // off=0x30a0
    coalition_t                                  coalition[2];                       // off=0x30c0
    queue_chain_t                                task_coalition[2];                  // off=0x3140
    uint64_t                                     dispatchqueue_offset;               // off=0x3240
    boolean_t                                    task_unnested;                      // off=0x3280
    int                                          task_disconnected_count;            // off=0x32a0
    void * __ptrauth(DA, true, 1f57)             hv_task_target;                     // off=0x32c0
    task_exc_guard_behavior_t                    task_exc_guard;                     // off=0x3300
    task_control_port_options_t                  task_control_port_options;          // off=0x3320
    queue_head_t                                 io_user_clients;                    // off=0x3340
    mach_vm_address_t                            mach_header_vm_address;             // off=0x33c0
    uint32_t                                     loadTag;                            // off=0x3400
    uint64_t                                     task_fs_metadata_writes;            // off=0x3440
    uint32_t                                     task_shared_region_slide;           // off=0x3480
    uuid_t                                       task_shared_region_uuid;            // off=0x34a0
    uint64_t                                     memstat_dirty_start;                // off=0x3540
    vmobject_list_output_t                       corpse_vmobject_list;               // off=0x3580
    uint64_t                                     corpse_vmobject_list_size;          // off=0x35c0
};
```
