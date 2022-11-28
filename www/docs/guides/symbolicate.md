---
hide_table_of_contents: true
description: How to symbolicate crashlogs.
---

# Symbolicate Crashlogs

> This is useful for symbolicating crashlogs you have collected from a device you don't have access to

`ipsw` will detect the `dyld_shared_cache` needed to symbolicate the **userspace** crashlog

```bash
❯ ipsw symbolicate solitaire-2021-02-23-185510.ips

   ⨯ please supply a dyld_shared_cache for iPhone12,1 running 14.5 (18E5154f)
```

You can download the current `beta` shared caches like so

```bash
❯ ipsw download ota --platform ios --device iPhone12,1 --beta --dyld
? You are about to download 1 OTA files. Continue? Yes
   • Parsing remote OTA        build=18E5154f device=iPhone12,1 iPhone11,8 version=iOS145DevBeta2
   • Extracting remote dyld_shared_cache (can be a bit CPU intensive)
```

```bash
❯ ipsw symbolicate solitaire-2021-02-23-185510.ips dyld_shared_cache_arm64e

Process:             solitaire [12345]
Hardware Model:      iPhone12,1
OS Version:          14.5
BuildID:             18E5154f

Exception Type:      EXC_BAD_ACCESS (SIGSEGV)
Exception Subtype:
KERN_INVALID_ADDRESS at 0x0000020000000010 -> 0x0000000000000010 (possible pointer authentication failure)
VM Region Info: 0x10 is not in any region.  Bytes before following region: 4363091952
      REGION TYPE                 START - END      [ VSIZE] PRT/MAX SHRMOD  REGION DETAIL
      UNUSED SPACE AT START
--->
      __TEXT                   1040f8000-1040fc000 [   16K] r-x/r-x SM=COW  ...app/solitaire

Termination Signal:  Segmentation fault: 11
Termination Reason:  Namespace SIGNAL, Code 0xb
Terminating Process: exc handler [12345]
Triggered by Thread: 45

Thread 45 name: Dispatch queue: CTTelephonyNetworkInfo
Thread 45 Crashed:
  0: libobjc.A.dylib         (slide=0x27010000) 0x1bc39e1e0 _objc_msgSend + 32
  1: CoreFoundation          (slide=0x27010000) 0x1a734e76c -[__NSDictionaryM objectForKeyedSubscript:] + 184
  2: CoreTelephony           (slide=0x27010000) 0x1a79d1230 -[CTTelephonyNetworkInfo updateRat:descriptor:] + 144
  3: CoreTelephony           (slide=0x27010000) 0x1a79d1114 -[CTTelephonyNetworkInfo queryRatForDescriptor:] + 164
  4: CoreTelephony           (slide=0x27010000) 0x1a79cfe9c -[CTTelephonyNetworkInfo connectionStateChanged:connection:dataConnectionStatusInfo:] + 72
  5: CoreFoundation          (slide=0x27010000) 0x1a7476894 ___invoking___ + 148
  6: CoreFoundation          (slide=0x27010000) 0x1a734a054 -[NSInvocation invoke] + 380
  7: CoreFoundation          (slide=0x27010000) 0x1a734a658 -[NSInvocation invokeWithTarget:] + 80
  8: CoreTelephony           (slide=0x27010000) 0x1a79d9fb0 __ZZN8dispatch5asyncIZ50-[CoreTelephonyClientMux sink:handleNotification:]E3$_2EEvP16dispatch_queue_sNSt3__110unique_ptrIT_NS4_14default_deleteIS6_EEEEENUlPvE_8__invokeESA_ + 44
  9: libdispatch.dylib       (slide=0x27010000) 0x1a705e878 __dispatch_client_callout + 20
 10: libdispatch.dylib       (slide=0x27010000) 0x1a7066060 __dispatch_lane_serial_drain + 620
 11: libdispatch.dylib       (slide=0x27010000) 0x1a7066c5c __dispatch_lane_invoke + 404
 12: libdispatch.dylib       (slide=0x27010000) 0x1a7071518 __dispatch_workloop_worker_thread + 764
 13: libsystem_pthread.dylib (slide=0x27010000) 0x1f33ba7a4 __pthread_wqthread + 276
 14: libsystem_pthread.dylib (slide=0x27010000) 0x1f33c174c _start_wqthread + 8

Thread 45 State:
    x0: 0x00000002803e0047   x1: 0x00000001f6df3124   x2: 0x0000000281ed4000   x3: 0x00000001b6efb344
    x4: 0x00000000000062dc   x5: 0x0000000000000001   x6: 0x3130303030303030   x7: 0x0000000000000000
    x8: 0x00000001f6df3000   x9: 0xdb6091bce8b38b12  x10: 0x6ae10002803e0047  x11: 0x0000000281ed4021
   x12: 0x0000000281ed4021  x13: 0x0000020000000000  x14: 0x00000001a7604012  x15: 0x0000020000000000
   x16: 0x0000000000000000  x17: 0xd0357901a735c988  x18: 0x0000000000000000  x19: 0x0000000281ed4000
   x20: 0x00000001f6df3124  x21: 0x0000000000000003  x22: 0x00000002801de580  x23: 0x0000000000000003
   x24: 0x0000000000000001  x25: 0x000000020abc3520  x26: 0x0000000000000003  x27: 0x0000000000000000
   x28: 0x0000000000000104   fp: 0x000000016de0e780   lr: 0x00000001a734e76c
    sp: 0x000000016de0e740   pc: 0x00000001bc39e1e0 cpsr: 0x20001000
   esr: 0x92000004
```

> **NOTE:** You can use the `--unslide` flag to unslide the crashlog for easier static analysis