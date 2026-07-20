#ifndef IPSW_FRIDA_CORE_COMPAT_H
#define IPSW_FRIDA_CORE_COMPAT_H

/* Hide Frida 17.16's new signature while importing the rest of the devkit. */
#define frida_device_enable_spawn_gating_sync \
  ipsw_frida_device_enable_spawn_gating_sync_v17
#include_next <frida-core.h>
#undef frida_device_enable_spawn_gating_sync

#if FRIDA_CHECK_VERSION(17, 16, 0)
extern void ipsw_frida_device_enable_spawn_gating_sync_v17(
    FridaDevice *device,
    FridaSpawnGatingOptions *options,
    GCancellable *cancellable,
    GError **error) __asm__("_frida_device_enable_spawn_gating_sync");

static inline void frida_device_enable_spawn_gating_sync(
    FridaDevice *device,
    GCancellable *cancellable,
    GError **error) {
  ipsw_frida_device_enable_spawn_gating_sync_v17(
      device, NULL, cancellable, error);
}
#else
extern void frida_device_enable_spawn_gating_sync(
    FridaDevice *device,
    GCancellable *cancellable,
    GError **error);
#endif

#endif
