/**
  *
  * A relatively simple program to home in on XNU's system call table.
  * Coded specifically for iOS kernels, but works just as well on OS X.
  * Seeks XNU version string and signature of beginning of system call table.
  * Then dumps all system calls. Can work on the kernel proper, or the kernel cache.
  *
  * System call names auto-generated from iOS's <sys/syscall.h>
  * (/Developer/Platforms/iPhoneOS.platform/DeviceSupport/Latest/Symbols/usr/include/sys)
  *
  * can also be generated from OS X's <sys/syscall.h>, with minor tweaks (e.g. include
  *  ledger, pid_shutdown_sockets, etc..)
  *
  * Note, that just because a syscall is present, doesn't imply it's implemented -
  *  System calls can either point to nosys, or can be stubs returning an error code,
  *  as is the case with audit syscalls (350-359), among others.
  *
  * Tested on iOS 2.0 through 9.3
  *
  * 03/20/14: Updated to dump sysctls, code cleaned, more messy code added
  *
  * 01/08/16: v2.0: dumps 64-bit, jtool companion file support
  *           v2.1: dumps MIG tables
  * 01/16/16:
  * ---------
  * This tool has been around for years, and I'm happy to know it helped people.
  * It does not promote piracy in any way, form, or manner.
  *
  * What it DOES promote, PROUDLY, is jailbreaking, and kernel research, in the
  * hands of the many, not the elitist, condescending little idiot that @i0n1c is.
  *
  * And if you have a problem with that, then tough.
  *
  * 03/17/16: v2.3b: symbolicates kext callouts, better resilience on bad Mach-O headers
  *
  * 06/16/16: And now that Apple decrypts its kernelcaches, this tool has become
  *           even more useful!
  *
  * 05/03/16: v2.3.1: correctly gets all kext names!
  * 05/27/16: Tight machlib integration, symbolicates by auto-disassembly with callbacks :-)
  *
  * 06/16/16  v3b2 (Hatsune): Allowed method switch, Fixed ID= in kexts, now handles 10b2
  *                           segment split kexts!
  *
  * 08/06/16: cykey fix (no crash on 32-bit), beta 3 with kpp finding
  *	      v2.2.1: kextracts
  *
  *
  * 08/21/16  v3b6 (Hatsune): Split kexts correctly reassembled. Symbolication needs to be fixed, though..
  *
  * 09/01/16  v3b8 (Hatsune): Got symbolication working, too
  *
  * 09/08/16  v3.0.1: Got Sandbox collections kind of working, and can now operate on complzss directly
  *
  *
  *
  * Coded by Jonathan Levin (a.k.a @Morpheus______), http://newosxbook.com
  *
  **/

#include <sys/mman.h> // For mmap(2)
#include <sys/stat.h> // For stat(2)
#include <unistd.h>   // For everything else
#include <fcntl.h>    // O_RDONLY
#include <stdio.h>    // printf!
#include <string.h>   // strstr..

#ifndef LINUX
#include <CoreFoundation/CoreFoundation.h>
#else
typedef unsigned char u_int8_t;
typedef unsigned int u_int32_t;
typedef unsigned long uint64_t;
typedef unsigned int uint32_t;

#define strnstr(a, b, c) strstr(a, b)
#endif

static int is64 = 0;
static int wantJToolOut = 0;

#define HAVE_LZSS
#ifdef HAVE_LZSS
#include "lzss.c"
#endif

// Mac Policy support

struct mac_policy_conf_64
{
    uint64_t mpc_name;            /** policy name */
    uint64_t mpc_fullname;        /** full name */
    uint64_t mpc_labelnames;      /** managed label namespaces */
    uint64_t mpc_labelname_count; /** number of managed label namespaces */
    uint64_t mpc_ops;             /** operation vector */
    uint64_t mpc_loadtime_flags;  /** load time flags */
    uint64_t mpc_field_off;       /** label slot */
    uint64_t mpc_runtime_flags;   /** run time flags */
    uint64_t mpc_list;            /** List reference */
    uint64_t mpc_data;            /** module data */
};                                // _mac_policy_conf_64

struct mac_policy_conf_32
{
    uint32_t mpc_name;            /** policy name */
    uint32_t mpc_fullname;        /** full name */
    uint32_t mpc_labelnames;      /** managed label namespaces */
    uint32_t mpc_labelname_count; /** number of managed label namespaces */
    uint32_t mpc_ops;             /** operation vector */
    uint32_t mpc_loadtime_flags;  /** load time flags */
    uint32_t mpc_field_off;       /** label slot */
    uint32_t mpc_runtime_flags;   /** run time flags */
    uint32_t mpc_list;            /** List reference */
    uint32_t mpc_data;            /** module data */
};                                // _mac_policy_conf_32

char *mac_policy_ops_names[] = {
    //"mpo_audit_check_postselect",
    "mpo_audit_check_preselect",
    "mpo_audit_check_preselect",
    "mpo_bpfdesc_label_associate",
    "mpo_bpfdesc_label_destroy",
    "mpo_bpfdesc_label_init",
    "mpo_bpfdesc_check_receive",
    "mpo_cred_check_label_update_execve",
    "mpo_cred_check_label_update",
    "mpo_cred_check_visible",
    "mpo_cred_label_associate_fork",
    "mpo_cred_label_associate_kernel",
    "mpo_cred_label_associate",
    "mpo_cred_label_associate_user",
    "mpo_cred_label_destroy",
    "mpo_cred_label_externalize_audit",
    "mpo_cred_label_externalize",
    "mpo_cred_label_init",
    "mpo_cred_label_internalize",
    "mpo_cred_label_update_execve",
    "mpo_cred_label_update",
    "mpo_devfs_label_associate_device",

    "mpo_devfs_label_associate_directory",
    "mpo_devfs_label_copy",
    "mpo_devfs_label_destroy",
    "mpo_devfs_label_init",
    "mpo_devfs_label_update",

    "mpo_file_check_change_offset",
    "mpo_file_check_create",
    "mpo_file_check_dup",
    "mpo_file_check_fcntl",
    "mpo_file_check_get_offset",
    "mpo_file_check_get",
    "mpo_file_check_inherit",
    "mpo_file_check_ioctl",
    "mpo_file_check_lock",
    "mpo_file_check_mmap_downgrade",
    "mpo_file_check_mmap",
    "mpo_file_check_receive",
    "mpo_file_check_set",
    "mpo_file_label_init",
    "mpo_file_label_destroy",
    "mpo_file_label_associate",

    "mpo_ifnet_check_label_update",
    "mpo_ifnet_check",
    "mpo_ifnet_label_associate",

    "mpo_ifnet_label_copy",
    "mpo_ifnet_label_destroy",
    "mpo_ifnet_label_externalize",
    "mpo_ifnet_label_init",
    "mpo_ifnet_label_internalize",
    "mpo_ifnet_label_update",
    "mpo_ifnet_label_recycle",

    "mpo_inpcb_check_deliver",
    "mpo_inpcb_label_associate",
    "mpo_inpcb_label_destroy",
    "mpo_inpcb_label_init",
    "mpo_inpcb_label_recycle",
    "mpo_inpcb_label_update",

    "mpo_iokit_check_device",

    "mpo_ipq_label_associate",
    "mpo_ipq_label_compare",
    "mpo_ipq_label_destroy",
    "mpo_ipq_label_init",
    "mpo_ipq_label_update",

    "mpo_reserved1_hook",
    "mpo_reserved2_hook",
    "mpo_reserved3_hook",
    "mpo_reserved4_hook",
    "mpo_reserved5_hook",
    "mpo_reserved6_hook",
    "mpo_reserved7_hook",
    "mpo_reserved8_hook",
    "mpo_reserved9_hook",

    "mpo_mbuf_label_associate_bpfdesc",
    "mpo_mbuf_label_associate_ifnet",
    "mpo_mbuf_label_associate_inpcb",
    "mpo_mbuf_label_associate_ipq",
    "mpo_mbuf_label_associate_linklayer",
    "mpo_mbuf_label_associate_multicast_encap",
    "mpo_mbuf_label_associate_netlayer",
    "mpo_mbuf_label_associate_socket",
    "mpo_mbuf_label_copy",
    "mpo_mbuf_label_destroy",
    "mpo_mbuf_label_init",

    "mpo_mount_check_fsctl",
    "mpo_mount_check_getattr",
    "mpo_mount_check_label_update",
    "mpo_mount_check_mount",
    "mpo_mount_check_remount",
    "mpo_mount_check_setattr",
    "mpo_mount_check_stat",
    "mpo_mount_check_umount",
    "mpo_mount_label_associate",
    "mpo_mount_label_destroy",
    "mpo_mount_label_externalize",
    "mpo_mount_label_init",
    "mpo_mount_label_internalize",

    "mpo_netinet_fragment",
    "mpo_netinet_icmp_reply",
    "mpo_netinet",

    "mpo_pipe_check_ioctl",
    "mpo_pipe_check_kqfilter",
    "mpo_pipe_check_label_update",
    "mpo_pipe_check_read",
    "mpo_pipe_check_select",
    "mpo_pipe_check_stat",
    "mpo_pipe_check_write",
    "mpo_pipe_label_associate",
    "mpo_pipe_label_copy",
    "mpo_pipe_label_destroy",
    "mpo_pipe_label_externalize",
    "mpo_pipe_label_init",
    "mpo_pipe_label_internalize",
    "mpo_pipe_label_update",

    "mpo_policy_destroy",
    "mpo_policy_init",
    "mpo_policy_initbsd",
    "mpo_policy_syscall",

    "mpo_system_check_sysctlbyname",
    "mpo_proc_check_inherit_ipc_ports",
    "mpo_vnode_check_rename",
    "mpo_kext_check_query",
    "mpo_iokit_check_nvram_get",
    "mpo_iokit_check_nvram_set",
    "mpo_iokit_check_nvram_delete",
    "mpo_proc_check_expose",
    "mpo_proc_check_set_host_special_port",
    "mpo_proc_check_set_host_exception_port",
    "mpo_reserved10_hook",
    "mpo_reserved11_hook",
    "mpo_reserved12_hook",
    "mpo_reserved13_hook",
    "mpo_reserved14_hook",
    "mpo_reserved15_hook",
    "mpo_reserved16_hook",
    "mpo_reserved17_hook",
    "mpo_reserved18_hook",
    "mpo_reserved19_hook",
    "mpo_reserved20_hook",
    "mpo_reserved21_hook",

    "mpo_posixsem_check_create",
    "mpo_posixsem_check_open",
    "mpo_posixsem_check_post",
    "mpo_posixsem_check_unlink",
    "mpo_posixsem_check_wait",
    "mpo_posixsem_label_associate",
    "mpo_posixsem_label_destroy",
    "mpo_posixsem_label_init",
    "mpo_posixshm_check_create",
    "mpo_posixshm_check_mmap",
    "mpo_posixshm_check_open",
    "mpo_posixshm_check_stat",
    "mpo_posixshm_check",
    "mpo_posixshm_check_unlink",
    "mpo_posixshm_label_associate",
    "mpo_posixshm_label_destroy",
    "mpo_posixshm_label_init",

    "mpo_proc_check_debug",
    "mpo_proc_check_fork",
    "mpo_proc_check_get_task_name",
    "mpo_proc_check_get_task",
    "mpo_proc_check_getaudit",
    "mpo_proc_check_getauid",
    "mpo_proc_check_getlcid",
    "mpo_proc_check_mprotect",
    "mpo_proc_check_sched",
    "mpo_proc_check_setaudit",
    "mpo_proc_check_setauid",
    "mpo_proc_check_setlcid",
    "mpo_proc_check_signal",
    "mpo_proc_check_wait",
    "mpo_proc_label_destroy",
    "mpo_proc_label_init",

    "mpo_socket_check_accept",
    "mpo_socket_check_accepted",
    "mpo_socket_check_bind",
    "mpo_socket_check_connect",
    "mpo_socket_check_create",
    "mpo_socket_check_deliver",
    "mpo_socket_check_kqfilter",
    "mpo_socket_check_label_update",
    "mpo_socket_check_listen",
    "mpo_socket_check_receive",
    "mpo_socket_check_received",
    "mpo_socket_check_select",
    "mpo_socket_check_send",
    "mpo_socket_check_stat",
    "mpo_socket_check_setsockopt",
    "mpo_socket_check_getsockopt",
    "mpo_socket_label_associate_accept",
    "mpo_socket_label_associate",
    "mpo_socket_label_copy",
    "mpo_socket_label_destroy",
    "mpo_socket_label_externalize",
    "mpo_socket_label_init",
    "mpo_socket_label_internalize",
    "mpo_socket_label_update",

    "mpo_socketpeer_label_associate_mbuf",
    "mpo_socketpeer_label_associate_socket",
    "mpo_socketpeer_label_destroy",
    "mpo_socketpeer_label_externalize",
    "mpo_socketpeer_label_init",

    "mpo_system_check_acct",
    "mpo_system_check_audit",
    "mpo_system_check_auditctl",
    "mpo_system_check_auditon",
    "mpo_system_check_host_priv",
    "mpo_system_check_nfsd",
    "mpo_system_check_reboot",
    "mpo_system_check_settime",
    "mpo_system_check_swapoff",
    "mpo_system_check_swapon",
    "mpo_reserved22_hook",

    "mpo_sysvmsg_label_associate",
    "mpo_sysvmsg_label_destroy",
    "mpo_sysvmsg_label_init",
    "mpo_sysvmsg_label_recycle",
    "mpo_sysvmsq_check_enqueue",
    "mpo_sysvmsq_check_msgrcv",
    "mpo_sysvmsq_check_msgrmid",
    "mpo_sysvmsq_check_msqctl",
    "mpo_sysvmsq_check_msqget",
    "mpo_sysvmsq_check_msqrcv",
    "mpo_sysvmsq_check_msqsnd",
    "mpo_sysvmsq_label_associate",
    "mpo_sysvmsq_label_destroy",
    "mpo_sysvmsq_label_init",
    "mpo_sysvmsq_label_recycle",
    "mpo_sysvsem_check_semctl",
    "mpo_sysvsem_check_semget",
    "mpo_sysvsem_check_semop",
    "mpo_sysvsem_label_associate",
    "mpo_sysvsem_label_destroy",
    "mpo_sysvsem_label_init",
    "mpo_sysvsem_label_recycle",
    "mpo_sysvshm_check_shmat",
    "mpo_sysvshm_check_shmctl",
    "mpo_sysvshm_check_shmdt",
    "mpo_sysvshm_check_shmget",
    "mpo_sysvshm_label_associate",
    "mpo_sysvshm_label_destroy",
    "mpo_sysvshm_label_init",
    "mpo_sysvshm_label_recycle",
    "mpo_reserved23_hook",
    "mpo_reserved24_hook",
    "mpo_reserved25_hook",
    "mpo_mount_check_snapshot_create",
    "mpo_check_snapshot_delete",
    "mpo_vnode_check_clone",
    "mpo_proc_check_get_cs_info",
    "mpo_proc_check_set_cs_info",

    "mpo_iokit_check_hid_control",

    "mpo_vnode_check_access",
    "mpo_vnode_check_chdir",
    "mpo_vnode_check_chroot",
    "mpo_vnode_check_create",
    "mpo_vnode_check_deleteextattr",
    "mpo_vnode_check_exchangedata",
    "mpo_vnode_check_exec",
    "mpo_vnode_check_getattrlist",
    "mpo_vnode_check_getextattr",
    "mpo_vnode_check_ioctl",
    "mpo_vnode_check_kqfilter",
    "mpo_vnode_check_label_update",
    "mpo_vnode_check_link",
    "mpo_vnode_check_listextattr",
    "mpo_vnode_check_lookup",
    "mpo_vnode_check_open",
    "mpo_vnode_check_read",
    "mpo_vnode_check_readdir",
    "mpo_vnode_check_readlink",
    "mpo_vnode_check_rename_from",
    "mpo_vnode_check_rename",
    "mpo_vnode_check_revoke",
    "mpo_vnode_check_select",
    "mpo_vnode_check_setattrlist",
    "mpo_vnode_check_setextattr",
    "mpo_vnode_check_setflags",
    "mpo_vnode_check_setmode",
    "mpo_vnode_check_setowner",
    "mpo_vnode_check_setutimes",
    "mpo_vnode_check_stat",
    "mpo_vnode_check",
    "mpo_vnode_check_unlink",
    "mpo_vnode_check_write",
    "mpo_vnode_label_associate_devfs",
    "mpo_vnode_label_associate_extattr",
    "mpo_vnode_label_associate_file",
    "mpo_vnode_label_associate_pipe",
    "mpo_vnode_label_associate_posixsem",
    "mpo_vnode_label_associate_posixshm",
    "mpo_vnode_label_associate_singlelabel",
    "mpo_vnode_label_associate_socket",
    "mpo_vnode_label_copy",
    "mpo_vnode_label_destroy",
    "mpo_vnode_label_externalize_audit",
    "mpo_vnode_label_externalize",
    "mpo_vnode_label_init",
    "mpo_vnode_label_internalize",
    "mpo_vnode_label_recycle",
    "mpo_vnode_label_store",
    "mpo_vnode_label_update_extattr",
    "mpo_vnode_label_update",
    "mpo_vnode_notify_create",
    "mpo_vnode_check_signature",
    "mpo_vnode_check_uipc_bind",
    "mpo_vnode_check_uipc_connect",

    "mpo_proc_check_run_cs_invalid",
    "mpo_proc_check_suspend_resume",

    "mpo_thread_userret",

    "mpo_iokit_check_set_properties",

    "mpo_system_check_chud",

    "mpo_vnode_check_searchfs",

    "mpo_priv_check",
    "mpo_priv_grant",
    "mpo_proc_check_map_anon",

    "mpo_vnode_check_fsgetpath",

    "mpo_iokit_check_open",

    "mpo_proc_check_ledger",

    "mpo_vnode_notify_rename",

    "mpo_vnode_check_setacl",

    "mpo_system_check_kas_info",

    "mpo_proc_check_cpumon",

    "mpo_vnode_notify_open",

    "mpo_system_check_info",

    "mpo_pty_notify_grant",
    "mpo_pty_notify_close",

    "mpo_vnode_find_sigs",

    "mpo_kext_check_load",
    "mpo_kext_check_unload",

    "mpo_proc_check_proc_info",
    "mpo_vnode_notify_link",
    "mpo_iokit_check_filter_properties",
    "mpo_iokit_check_get_property",

    NULL

};

#include <mach-o/loader.h> // struct mach_header
#include "machlib.h"       // from jtool
#include "common.h"        // from jtool
#include "companion.h"     // from jtool
#include "jtoolsyms.h"

int jtoolOutFD = 0;

char *mmapped = NULL;
int xnu3757_and_later = 0;
int g_jdebug = 0;
int g_dec = 0;
uint64_t prelink_data_data_addr = 0;
uint64_t prelink_data_data_offset = 0;
uint64_t prelink_data_data_size = 0;
struct symtabent *kernelSymTable = NULL;

void register_disassembled_function_call_callback(void *Func);
char *filename = NULL;

void **segments = NULL;

typedef struct
{

    char *sig;
    char *name;

} kext_sig;

// 2.3 kext sigs

kext_sig KextSigs[] = {

    // The Magnificent Seven can be identified by their symbols (supported in all archs :)
    // plus by the fact that they have no __TEXT.__cstring

    {"MD5Init", "Libkern Pseudoextension (com.apple.kpi.libkern)"},
    {"lock_get_calendar_microti", "Mach Kernel Pseudoextension (com.apple.kpi.mach)"},
    {"IOBSDNameMatching", "I/O Kit Pseudoextension"},
    {"VNOP_BWRITE", "BSD Kernel Pseudoextension (com.apple.kpi.bsd)"},
    {"ifnet_poll_params", "Private Pseudoextension (com.apple.kpi.private)"},
    {"KUNCExecute", "Unsupported Pseudoextension (com.apple.kpi.unsupported)"},
    {"mac_iokit_check_nvram", "MAC Framework Pseudoextension (com.apple.kpi.dsep)"},

    {"com.apple.driver.AppleSynopsysMIPIDSI", "(com.apple.driver.AppleSynopsysMIPIDSI)"},
    {"com.apple.nke.pptp", "(com.apple.nke.pptp)"},
    {"com.apple.kec.Libm", "com.apple.kec.Libm"},
    {"com.apple.driver.AppleEmbeddedAccelerometer", "(com.apple.driver.AppleEmbeddedAccelerometer)"},
    {"com.apple.driver.AppleSamsungI2S", "(com.apple.driver.AppleSamsungI2S)"},
    {"com.apple.driver.AppleT7000PMGR", "(com.apple.driver.AppleT7000PMGR)"},
    {"com.apple.driver.AppleS5L8960XUSBEHCI", "(com.apple.driver.AppleS5L8960XUSBEHCI)"},
    {"com.apple.driver.AppleT7000CLPC", "(com.apple.driver.AppleT7000CLPC)"},
    {"com.apple.driver.AppleT7000", "(com.apple.driver.AppleT7000)"},
    {"com.apple.driver.AppleS5L8960XUSBHSIC", "(com.apple.driver.AppleS5L8960XUSBHSIC)"},
    {"com.apple.driver.AppleUSBHSIC", "(com.apple.driver.USBHSIC)"},
    {"com.apple.driver.AppleUSBEHCIARM", "(com.apple.driver.AppleUSBEHCIARM)"},
    {"com.apple.driver.AppleS5L8960XGPIOIC", "(com.apple.driver.AppleS5L8960XGPIOIC)"},
    {"com.apple.driver.AppleInterruptController", "(com.apple.driver.AppleInterruptController)"},
    {"com.apple.driver.DiskImages.ReadWriteDiskImage", "(com.apple.driver.DiskImages.ReadWriteDiskImage)"},
    {"com.apple.iokit.IOMikeyBusFamily", "(com.apple.iokit.IOMikeyBusFamily)"},
    {"com.apple.iokit.AppleARMIISAudio", "(com.apple.iokit.AppleARMIISAudio)"},
    {"com.apple.driver.AppleEmbeddedAudio", "(com.apple.driver.AppleEmbeddedAudio)"},
    {"com.apple.driver.AppleCS35L19Amp", "(com.apple.driver.AppleCS35L19Amp)"},
    {"com.apple.AppleFSCompression.AppleFSCompressionTypeZlib", "(com.apple.AppleFSCompression.AppleFSCompressionTypeZlib)"},
    {"com.apple.nke.l2tp", "(com.apple.nke.l2tp)"},

    // Others have very unique strings
    {"bsdthread_terminate", "Pthread (com.apple.kec.pthread)"},
    // All the rest can be identified by their IO Objects (can't obfuscate this, AAPL.. ;-)
    // or other strings (in cases where they're still chatty)

    {"lzvn_decode"
     "AppleFSCompressionTypeZlib (com.apple.AppleFSCompressionTypeZlib)"},

    {"AppleVXD393PriorityQueue", "AppleVXD393 (com.apple.driver.AppleVXD393)"},
    {"AppleS5L8940XDWI", "AppleS5L8940XDWI (com.apple.driver.AppleS5L8940XDWI)"},
    {"AppleD2186PMU", "AppleD2186PMU (com.apple.driver.AppleD2186PMU)"},
    {"AppleDialogPMU::", "AppleDialogPMU (com.apple.driver.AppleDialogPMU)"},

    {"com_apple_driver_KeyDeliveryIOKitMSE", "LSDIOKitMSE (com.apple.driver.LSDIOKitMSE)"},
    {"com_apple_driver_KeyDeliveryIOKit", "LSDIOKit (com.apple.driver.LSDIOKit)"},

    {"Sandbox extension sentinel", "Seatbelt (com.apple.security.sandbox)"},
    {"IOSlowAdaptiveClockingDomain", "IOSlowAdaptiveClockingFamily  (com.apple.iokit.IOSlowAdaptiveClockingFamily)"},
    {"AppleSEPManager::", "AppleSEPManager (com.apple.driver.AppleSEPManager)"},
    {"AppleSEPKeyStore::", "AppleSEPKeyStore (com.apple.driver.AppleSEPKeyStore)"},
    {"AppleOscarAsyncEventSource", "AppleOscar (com.apple.driver.AppleOscar)"},
    {"IOSurface::", "IOSurface (com.apple.iokit.IOSurface)"},

    {"AppleS5L8960XDART::", "AppleS5L8960XDART (com.apple.driver.AppleS5L8960XDART)"}, // 42
    {"IODART::", "IODARTFamily (com.apple.driver.IODARTFamily)"},
    {"IOBlockStorageDriver]:", "I/O Kit Storage Family (com.apple.iokit.IOStorageFamily)"}, // 43
    {"IOHDIXControllerUserClient::", "AppleDiskImageDriver (com.apple.driver.DiskImages)"},
    {"IOHDIXHDDriveInKernel", "AppleDiskImagesKernelBacked (com.apple.driver.DiskImages.KernelBacked)"}, // 45

    {"KDIRAMBackingStore", "AppleDiskImagesRAMBackingStore (com.apple.driver.DiskImages.RAMBackingStore)"},

    {"AppleAJPEGHal::", "AppleJPEGDriver (com.apple.driver.AppleJPEGDriver)"}, // 47
    {"AppleUSBHostMergePropertie", "I/O Kit Driver for USB Devices (com.apple.driver.AppleUSBHostMergeProperties)"},

    {"IOUSBDeviceConfigurator:", "IOUSBDeviceFamily (com.apple.iokit.IOUSBDeviceFamily)"},
    {"ORS232SerialStreamSync", "IOKit Serial Port Family (com.apple.iokit.IOSerialFamily)"},
    {"AppleOnboardSerialBSDClient:", "AppleOnboardSerial (com.apple.driver.AppleOnboardSerial)"},
    {"AppleS5L8940XI2CController:", "AppleS5L8940XI2CController (com.apple.driver.AppleS5L8940XI2C)"},

    {"AppleCS46L71Device", "AppleCS42L71Audio (com.apple.driver.AppleCS42L71Audio)"},
    {"AppleCS46L21Device", "AppleCS42L21Audio (com.apple.driver.AppleCS42L21Audio)"},
    {"IOAccessoryPrimaryDevicePort", "IOAccessoryManager (com.apple.iokit.IOAccessoryManager)"},

    //AppleBasebandPCIPDPManager/com.apple.driver.AppleBasebandPCIMAVPDP AppleSSE/com.apple.driver.AppleSSE nke.tls

    {"AppleSynopsysOTG3Device", "AppleSynopsysOTGDevice (com.apple.driver.AppleSynopsysOTGDevice)"},
    {"CCLogStream:", "CoreCapture (com.apple.driver.CoreCapture)"},
    {"CoreCaptureResponder", "CoreCaptureResponder (com.apple.driver.CoreCaptureResponder)"},

    {"com_apple_driver_FairPlayIOKitUserClient", "FairPlayIOKit (com.apple.driver.FairPlayIOKit)"},
    {"AppleTVIRUserClient", "AppleTVIR (com.apple.driver.AppleTVIR)"}, // TvOS
    {"AppleMobileApNonce::"
     "AppleMobileApNonce (com.apple.driver.AppleMobileApNonce)"},
    {"AppleStorageProcessorNode", "AppleStorageProcessorNodes (com.apple.driver.ASPSupportNodes"},
    {"ApplePinotLCD:", "ApplePinotLCD (com.apple.driver.ApplePinotLCD)"},
    {"IOAccelDevice", "IOAcceleratorFamily (com.apple.iokit.IOAcceleratorFamily2)"},
    {"AppleUSBEthernetHost::", "AppleUSBEthernetHost (com.apple.driver.AppleUSBEthernetHost"},
    {"AppleIDAMInterface", "AppleIDAMInterface (com.apple.driver.AppleIDAMInterface)"},
    {"com.apple.kext.tlsnke", "TLS NKE (com.apple.kext.tlsnke)"},
    {"AppleSSEUserClient", "AppleSSE (com.apple.driver.AppleSSE)"},
    {"AppleM2Scaler", "Apple M2 Scaler and Color Space Converter Driver (com.apple.driver.AppleM2ScalerCSCDriver)"},
    {"IOStreamAudio", "IOStreamAudioFamily (com.apple.iokit.IOStreamAudioFamily)"},
    {"Cyclone", "AppleCycloneErrorHandler (com.apple.driver.AppleCycloneErrorHander"},
    {"IOAudio2TransformerUserClient", "IOAudio2Family (com.apple.iokit.IOAudio2Family)"},
    {"IOCECUserClient::", "IOCECFamily (com.apple.iokit.IOCECFamily)"},
    {"IOAVController", "IOAVFamily (com.apple.iokit.IOAVFamily)"},
    {
        "AppleDiagnosticDataAccessReadOnly",
        "AppleDiagnosticDataAcccessReadOnly (com.apple.driver.AppleDiagnosticDataAccessReadOnly",
    }, // 174
    {"AppleBiometricServices", "AppleBiometricServices (com.apple.driver.AppleBiometricServices)"},
    {"IOPDPPlumbers::", "AppleBasebandPCI (com.apple.driver.AppleBasebandPCI"},
    {"IOMobileFramebufferUserClient::", "IOMobileGraphicsFamily (com.apple.iokit.IOMobileGraphicsFamily)"}, // 26
    {"AppleMobileADBE0", "AppleH8ADBE0 (com.apple.driver.AppleH8ADBE0)"},
    {"IOEthernetController:", "I/O Kit Networking Family (com.apple.iokit.IONetworkingFamily)"},

    {"ApplePMGR::", "ApplePMGR (com.apple.driver.ApplePMGR)"},
    {"AppleS8000PMGR:", "AppleS8000PMGR (com.apple.driver.AppleS8000PMGR)"},
    {"IOPCIDevice::", "I/O Kit PCI Family (com.apple.iokit.IOPCIFamily)"},
    {"AppleS800xPCIe:", "AppleS8000PCIe (com.apple.driver.AppleS8000PCIe)"}, // 35
    {"AppleSPIBiometricSensor:", "AppleBiometricSensor (com.apple.driver.AppleBiometricSensor)"},
    {"ProvInfo", "ProvInfoIOKit (com.apple.driver.ProvInfoIOKit)"}, // 40

    {"AppleBCMWLANTimeKeeper", "AppleBCMWLANCore (com.apple.driver.driver.AppleBCMWLANCore)"},
    {"AppleBCMWLANChipManagerPCIe", "AppleBCMWLANBusInterfacePCIe (com.apple.driver.driver.AppleBCMWLANBusInterfacePCIe)"},

    {"AppleStockholmControlUserClient", "AppleStockholmControl (com.apple.driver.AppleStockholmControl)"},
    {"AppleMesaSEPDriver", "AppleMesaSEPDriver (com.apple.driver.AppleMesaSEPDriver)"}, // also found in StockholmControl...

    // Die, Die, DIE, YOU $%#$%$##$%!!!!!
    {"AppleMobileFileIntegrityUser", "AppleMobileFileIntegrity (com.apple.driver.AppleMobileFileIntegrity)"},

    {"AppleEmbeddedI2CLightSensor", "AppleEmbeddedLightSensor (com.apple.driver.AppleEmbeddedLightSensor)"},

    // Make this T7/8/9 agnostic by looking at suffix..
    {"TempSensorUserClient", "AppleEmbeddedTempSensor (com.apple.driver.AppleEmbeddedTempSensor)"},
    {
        "IONetworkUserClient",
        "iokit.IONetworkingFamily)",
    },
    {"corecrypto_kext", "corecrypto (com.apple.kec.corecrypto)"},
    {"IOReportFamily", "IOReportFamily (com.apple.iokit.IOReportFamily)"},
    {"AppleARMCPU", "AppleARMPlatform (com.apple.driver.AppleARMPlatform)"},
    {"AppleSamsungSPI", "AppleSamsungSPI (com.apple.driver.AppleSamsungSPI)"},
    {"IOAESAccelerator::", "IOAESAccelerator"},
    {"AppleEffaceableStorageUserClient::", "AppleEffaceableStorage (com.apple.driver.AppleEffaceableStorage)"},
    {"AppleH6CamIn::", "AppleH6CamIn"},
    {"AppleUSB20HubPort", "AppleUSB20HubPort"},
    {"IO80211AWDLMulti", "AWDL"},
    {"AppleUSBHostDevice", "AppleUSBHostDevice"},
    {"KDIUDIFDiskImage", "KDIUDIFDiskImage"},
    {"AppleUSBDeviceMux", "AppleUSBDeviceMux"},
    {"mDNSOffloadUserClient:", "mDNSOffloadUserClient"},
    {"AppleNANDConfigAccess", "AppleNANDConfigAccess"},
    {"AGXFirmwareKextG4P", "AGXFirmwareKextG4P"}, // AppleTV
    {"BTReset", "BlueTooth-unknown-yet"},

    {"AppleS5L8920XPWM", "AppleS5L8920XPWM (com.apple.driver.AppleS5L8920XPWM)"},
    {"AppleSN2400ChargerFunction", "AppleSN2400Charger (com.apple.driver.AppleSN2400Charger)"},
    {"AppleIPAppenderUserClient", "AppleIPAppender (com.apple.driver.AppleIPAppender)"},
    {"AppleMultitouchSPI", "AppleMultitouchSPI (com.apple.driver.AppleMultitouchSPI)"},

    {"H264IOSurfaceBuf", "H264 Video Encoder (com.apple.driver.AppleAVE)"},
    {"IOSlaveMemory", "IOSlaveProcessor (com.apple.driver.IOSlaveProcessor)"},
    {"ApplePCIEMSIController", "ApplePCIEMSIController (com.apple.driver.AppleEmbeddedPCIE)"},
    {"IOHIDLibUserClient", "IOHIDFamily (com.apple.iokit.IOHIDFamily)"},
    {"AppleA7IOP", "AppleA7IOP (com.apple.driver.AppleA7IOP)"},

    {NULL, NULL}};

int g_kct = 0;
char *g_kcs;

char *getKernelCacheStart(void) { return g_kcs; }

void setKernelCacheStart(char *Cache) { g_kcs = Cache; }

int getKernelCacheArch(void)
{
    return g_kct;
}

void setKernelCacheArch(int Kct)
{
    g_kct = Kct;
}
char *getPtr(char *mmapped, uint64_t loadAddr, uint64_t ptr)
{
    if (!ptr)
        return NULL;
    printf("...Getting value : %p\n", ptr);
    uint32_t off = 0;
    char *sect = MachOGetSectionNameContainingAddress(ptr);
    uint64_t addr = MachOGetSectionAddr(mmapped, sect);

    if (sect)
    {
        off = MachOGetSectionOffset(mmapped, sect);
    }

    if (off)
        return (mmapped + (ptr - addr) + off);
    else
        return 0;
}

void dumpOps(void *OpsPtr)
{
    // Assuming 64 for now

    int op = 0;
    uint64_t *ops = (uint64_t *)OpsPtr;
    while (mac_policy_ops_names[op])
    {

        if (ops[op])
        {
            if (jtoolOutFD)
            {
                char buf[1024];
                sprintf(buf, "0x%llx:_%s\n", ops[op], mac_policy_ops_names[op]);
                write(jtoolOutFD, buf, strlen(buf));
            }
            else
                printf("\t\t0x%llx:%s (%d)\n", ops[op], mac_policy_ops_names[op], op);
        }
        op++;
    }

    if (op)
        fprintf(stderr, "Dumped %d MAC Policy ops!\n", op);

    return;
};

#ifndef NOSB
#define MAX_SB_OPERATION_NAMES 200 // should last until Sandbox-949, at current rate of expansion :-)
int num_sandbox_operations = 0;

int profile_size = 0;
char **sb_operation_names = NULL;

int doSandboxOperationNames(char *KextBundleHeader, char *Segment)
{
    // Also Only in 64, at least for now
    if (!is64)
        return 0;

    // Structured approach would be parsing __DATA.__const and getting the pointers to
    // the strings. Faster, though, is to get the CStrings directly.

    // No risk of AAPL pulling operation names - they need them in kext for sandbox_check :-)

    struct section_64 *sec64TC = MachOGetSection(Segment);
    if (!sec64TC)
    {
        fprintf(stderr, "Unable to get operation names from %s\n", Segment);
        return 1;
    }

    char *opName = memmem(KextBundleHeader + sec64TC->offset,
                          sec64TC->size,
                          "default\0",
                          8);

    if (!opName)
    {
        fprintf(stderr, "Unable to find default profile name in %s\n", Segment);
        return 1;
    }

    // Get operation names
    sb_operation_names = calloc(MAX_SB_OPERATION_NAMES, sizeof(char *));

    sb_operation_names[0] = opName; // "default"
    opName += (strlen(opName) + 1);

    int done = 0;
    int name = 0;
    for (name = 1;
         name < MAX_SB_OPERATION_NAMES && !done;
         name++)
    {

        sb_operation_names[name] = opName;
        if (strstr(opName, "system-swap"))
            done++;

        opName += (strlen(opName) + 1);
    }

    num_sandbox_operations = name;
    profile_size = (num_sandbox_operations + 1) + 1; // this is shorts, remember!

    fprintf(stderr, "Expecting profile size to be %d shorts\n", profile_size);

    return 0;
};

int doSandboxProfiles(char *KextBundleHeader, char *Section)
{
    // Also Only in 64, at least for now
    if (!is64)
        return 0;

    struct section_64 *sec64TC = MachOGetSection(Section);
    uint64_t addr = sec64TC->addr;

    int off = sec64TC->offset;
    int size = sec64TC->size;

    uint64_t zeros[2] = {0};
    //uint16_t *profiles = memmem(KextBundleHeader + off,  size, "\x02\x00\x88\x00\x9c\x86\x00\x00", 8);

    char *profiles = memmem(KextBundleHeader + off, size, zeros, 16);
    profiles = memmem(profiles + 16, size, zeros, 16);

    if (!profiles)
    {
        fprintf(stderr, "FUD! Can't get profiles.. Please tell J about it and submit a sample!\n");
        return 1;
    }
    profiles += 16;

    addr += (profiles - (KextBundleHeader + off));
    // Otherwise
    uint16_t numProfiles = *((uint16_t *)(profiles + 10));
    uint16_t *prof = (uint16_t *)(profiles + 12); // to point to 0x869c
    int done = 0;

    printf("Found profiles at offset %x, vmaddr %llx\n",
           profiles - KextBundleHeader, addr);
    printf("Got %d (0x%x) profiles, of size %d bytes each\n", numProfiles, numProfiles, profile_size * 2);
    int profNum = 0;
    uint16_t *lastProf = 0;

    //int profile_size = 0x85; // In XNU 37xx and later, as measured in shorts

    while (profNum < numProfiles && !done)
    {

        char *profName = (profiles + (*prof * 8)) + 4;
        if (*profName)
        {

            printf("Got profile:0x%03hx = %llx - ", *prof, addr + (*prof * 8));
            printf("%s\n", profName);
            if ((lastProf) && ((prof - lastProf) != profile_size))
            {
                fprintf(stderr, "Warning: Profiles are 0x%x (not 0x%hx,  %d) apart\n",
                        (prof - lastProf), profile_size, profile_size);
            }
            int op = 0;
            for (op = 0; op < num_sandbox_operations; op++)
            {
                printf("%s:%s:", profName, sb_operation_names[op]);

                uint16_t first = *((uint16_t *)(profiles + (*(prof + 2 + op) * 8)));
                uint16_t second = *((uint16_t *)(profiles + (*(prof + 2 + op) * 8)) + 1);

                int resolved = 0;
                if (first == 1)
                {
                    if (second == 5)
                    {
                        printf("deny");
                        resolved++;
                    }
                    else if (second == 0)
                    {
                        printf("allow");
                        resolved++;
                    }
                }
                if (!resolved)
                {
                    printf( //" *0x%llx = "
                        " %04hx %04hx",
                        //(addr + (*(prof + 2 + op) * 8)),
                        first, second);

                    if (second > 0x6400)
                        printf("(%llx)",
                               addr + (second * 8));
                }

                printf("\n");
            }

            profNum++;
            lastProf = prof;
        }

        else
        {
            printf("Got Profile, but no name\n");
        }
        prof += profile_size;
    }

#if 0
	// For now, just use "AGXCompiler" as a hook
	char *profiles = memmem(KextBundleHeader,  size,
				"\x13\x00\x00\x00\x41\x47\x58\x43",
				 8);

	if (!profiles)
	{
		fprintf(stderr,"FUD! Can't get profiles.. Please tell J about it and submit a sample!\n");
		return 1;
	}

	else fprintf(stderr,"Got it\n");

	// Ok. So we have our start.

	char *currProfile = profiles;

	int test = 0;

	for (test = 0 ; test < 1700; test ++)
	{
	uint32_t *len = (uint32_t *) currProfile;
	char *name = (char *) (len + 1);

	if (*len == 7) {currProfile += 8; continue; }
 	printf ("Len: %d, Name: %s\n", *len,name);

	if (name[*len-1] == '\xa') { printf("OK\n");}
	else printf("NOT OK %x\n", name [*len-1]);

	currProfile = name + *len ;

	// Need to pad to 8
	uint64_t pad = 8 - (((uint64_t) currProfile) % 8);
	if (pad !=8) currProfile += pad;

	printf ("Next: 0x%llx\n", (currProfile - profiles));

	}

#endif

    return (0);
} // doSandboxProfiles

#endif // NOSB
int doPolicyOps(char *KextBundleHeader, char *Segment)
{
    // Only in 64
    if (!is64)
        return 0;
    struct section_64 *sec64TC = MachOGetSection((unsigned char *)"__TEXT.__cstring");
    struct section_64 *sec64DC = MachOGetSection((unsigned char *)Segment);
    int doIt = 1;
    int foundPolicy = 0;

    if (!sec64TC)
    {
        doIt = 0;
        fprintf(stderr, "Unable to get __TEXT.__cstring from kext - not symbolicating\n");
    };
    if (!sec64DC)
    {
        doIt = 0;
    }

    if (doIt)
    {

        int off = sec64DC->offset;
        int size = sec64DC->size;

        uint64_t *lookForAMFI = (uint64_t *)(KextBundleHeader + sec64DC->offset);
        int i = 0;
        for (i = 0;
             i < sec64DC->size / 8;
             i++)
        {
            if (*lookForAMFI && *lookForAMFI > sec64TC->addr &&
                *lookForAMFI < sec64TC->addr + sec64TC->size)
            {
                char *str = KextBundleHeader + sec64TC->offset + (*lookForAMFI - sec64TC->addr);

                if ((strcmp(str, "AMFI") == 0) || (strcmp(str, "Sandbox") == 0))
                {

                    fprintf(stderr, "Found policy at %p\n", sec64DC->addr + i * sizeof(uint64_t));
                    struct mac_policy_conf_64 *mpc64 = (struct mac_policy_conf_64 *)lookForAMFI;

                    printf("\tPolicy name: %s\n", getPtr(KextBundleHeader, sec64TC->addr - sec64TC->offset, mpc64->mpc_name));

                    //	  printf("\tFull name of policy: %s\n",	 getPtr (KextBundleHeader, sec64TC->addr - sec64TC->offset, mpc64->mpc_fullname));

                    printf("\tFlags: %llx\n", mpc64->mpc_loadtime_flags);
                    //*((uint64_t *) 	 getPtr (KextBundleHeader, sec64TC->addr - sec64TC->offset, mpc64->mpc_ops)));

                    if ((mpc64->mpc_ops & 0xffffff8000000000) == 0xffffff8000000000)
                    {
                        printf("\tOps: %llx\n", mpc64->mpc_ops);

                        dumpOps(getPtr(KextBundleHeader, sec64DC->addr - sec64DC->offset, mpc64->mpc_ops));
                    }

                    foundPolicy++;
                }
            }
            lookForAMFI++;
        }
    }
    return (foundPolicy);
}

char *identifyKextNew(char *KextBundleHeader, int Size, char *KernelCache)
{
    static char returned[1024];
    // Look at first page of Kext header
    if (Size < 0x1000)
    {
        return ("this kext is too small!\n");
    }

    // MUCH better method: look at kext's __DATA.__data.
    // This is guaranteed  (well, mostly :-) to contain a com.apple...
    // something

    // So we process header, and get section data. Then get __DATA.__data
    // and isolate "com.apple.XXXXXXX"

    if (g_jdebug)
        fprintf(stderr, "Processing kext...\n");
    segments = processFile((unsigned char *)KextBundleHeader, Size, getKernelCacheArch(), 0, 0, 0);

    uint32_t __DATA__data_off = MachOGetSectionOffset((unsigned char *)KextBundleHeader, "__DATA.__data");
    uint32_t __DATA__data_size = MachOGetSectionSize((unsigned char *)KextBundleHeader, "__DATA.__data");

    uint32_t __DATA__CONST_const_off = MachOGetSectionOffset((unsigned char *)KextBundleHeader, "__DATA_CONST.__const");

    struct source_version_command *svc = (struct source_version_command *)findLoadCommand((unsigned char *)KextBundleHeader, LC_SOURCE_VERSION, NULL);

    uint32_t __DATA__CONST_const_size = 0;
    if (__DATA__CONST_const_off)
    {

        __DATA__CONST_const_size = MachOGetSectionSize((unsigned char *)KextBundleHeader, "__DATA_CONST.__const");
        if (g_jdebug)
        {
            fprintf(stderr, "\ngot data const of kext %d at offset %d:\n", __DATA__CONST_const_size, __DATA__CONST_const_off);
            //	write (2, (unsigned char *) KernelCache+ __DATA__CONST_const_off, __DATA__CONST_const_size);
        }
        if (svc)
        {
            sprintf(returned, "Unknown(%ld.%d.%d.%d.%d)",
                    (long)((svc->version) >> 40),
                    (int)(svc->version >> 30) & 0x000003FF,
                    (int)(svc->version >> 20) & 0x000003FF,
                    (int)(svc->version >> 10) & 0x000003FF,
                    (int)(svc->version) & 0x000003FF);
        }
    }

    if (!__DATA__data_off || !__DATA__data_size)
    {
        if (g_jdebug)
        {
            fprintf(stderr, "Unable to find __DATA.__data (%d, %d\n",
                    __DATA__data_off, __DATA__data_size);
            return (NULL);
        }
    }

    else if (g_jdebug)
    {
        fprintf(stderr, " __DATA.__data is @0x%x, Size %d bytes, Kext Size %d bytes\n",
                __DATA__data_off, __DATA__data_size, Size);
    }

    if (__DATA__data_size > Size)
    {
        fprintf(stderr, "__DATA.__data size is %d, but total kext size is %d. Something is wrong with this\n");
        return (NULL);
    }

    char *WhereFrom = (__DATA__CONST_const_off ? KernelCache : KextBundleHeader);

    char *bundle = memmem(WhereFrom + __DATA__data_off, __DATA__data_size,
                          "com.apple.", strlen("com.apple."));

    if (g_jdebug)
    {
        fprintf(stderr, "\n...got data data of kext %d at offset %d:\n", __DATA__data_size, __DATA__data_off);
        //
    }

    char *lastmatch = NULL;

    //if (!bundle) { fprintf(stderr,"NO BUNDLE\n");}
    //else { fprintf(stderr," SO FAR OK\n");}

    while (bundle)
    {
        lastmatch = bundle;
        if (strcmp(bundle, "com.apple.security.sandbox") == 0)
            break;
        if (g_jdebug)
        {
            printf("Match: %s\n", lastmatch);
        }
        bundle = memmem(lastmatch + 1, (__DATA__data_size - (lastmatch - bundle)),
                        "com.apple.", strlen("com.apple."));
    }

    char *name = lastmatch;

    // Even without kextracting we can use symbols in the kext to figure
    // out symbols in the kernel. This is because, even though kexts are
    // prelinked, stubs remain (you going to fix this now back at cupertino? ;-)

    if (name && (strstr(name, "AppleMobileFile") ||
                 (strstr(name, "sandbox"))))
    {
        // From AMFI and Sandbox we can find mac_policy_register.
        // This requires a little effort: First, get the policy from __DATA.__const,
        // then disassemble to find where it is passed as a first argument
        // then symbolicate both the stub, and the kernel symbol
        char *segName = "__DATA.__const";

        xnu3757_and_later = MachOGetSection("__DATA_CONST.__const");
        if (xnu3757_and_later)
        {
            segName = "__DATA_CONST.__const";
        }
        int foundPolicy = doPolicyOps(KextBundleHeader, segName);

        if (!foundPolicy && !xnu3757_and_later)
        {
            foundPolicy = doPolicyOps(KextBundleHeader, "__DATA.__data");

            if (foundPolicy)
                fprintf(stderr, "Found policy in __DATA.__data\n");
        }
        else
        {
            fprintf(stderr, "Found policy in %s\n", segName);
        }

        if (!foundPolicy && !strstr(name, "AppleMobileFile"))
        {
            fprintf(stderr, "MAC policy not found. This is fine for kernels prior to iOS 9.2, but please let J know if yours is newer\n");
        }
    } // AppleMobile

    if (name)
    {
        strncpy(returned, name, 1024);
    }
    else
        return (NULL); // strcpy(returned, "built-in?");

    if (svc)
    {
        sprintf(returned + strlen(returned), "(%ld.%d.%d.%d.%d)",
                (long)((svc->version) >> 40),
                (int)(svc->version >> 30) & 0x000003FF,
                (int)(svc->version >> 20) & 0x000003FF,
                (int)(svc->version >> 10) & 0x000003FF,
                (int)(svc->version) & 0x000003FF);
    }

    if (((svc->version >> 40) >= 570) && (name && (strstr(name, "sandbox"))))
    {
        fprintf(stderr, "This is the sandbox.kext, version %ld - Trying to get seatbelt-profiles\n",
                svc->version >> 40);

        if (doSandboxOperationNames(KextBundleHeader, "__TEXT.__cstring"))
        {
            fprintf(stderr, "Can't get profiles with sandbox operation names\n");
        }
        else
            doSandboxProfiles(KextBundleHeader, "__TEXT.__const");
    }

    return (returned);
};

char *identifyKext(char *KextBundleHeader, int Size)
{

    // Look at first page of Kext header
    if (Size < 0x1000)
    {
        return ("this kext is too small!\n");
    }

    // This is CRUDE. I know. But hey, it works. It could be optimized in several ways,
    // including:
    //
    //	A) bailing on a false positive
    //	B) marking out kexts already found and skipping them
    // and most importantly -
    //      C) Use machlib to just sift through the TEXT.__cstring section!
    //
    //  (but this is fast, and works!)
    int i = 0;
    for (i = 0;
         KextSigs[i].sig;
         i++)
    {
        if (memmem(KextBundleHeader, Size, KextSigs[i].sig, strlen(KextSigs[i].sig)))
            return KextSigs[i].name;
    }
    return NULL;
}
// 2.4

// For 64-bit
char output[1024];
int function_identifier(char *Symbol, uint64_t *Regs, int Call)
{

    static int panic = 0;
    // fprintf(stdout,"Called back : %llx\n", Regs[0]);

    if (Regs[R0] > 0xfffffff000000000)
    {

        // @Todo: > 0xxx.... size of text cstring, also optimize func, mark checks
        // in array when check done so can skip
        char *sect = MachOGetSectionNameContainingAddress(Regs[0]);
        if (sect && (strcmp(sect, "__TEXT.__cstring") == 0))
        {
            char *str = getPointerToAddr(Regs[0]);

            if ((!panic) && strcmp(str, "\"%s[KERNEL]: %s\"") == 0)
            {
                fprintf(stderr, "GOT panic: 0x%llx\n", Regs[32]);
                sprintf(output, "_panic");
                addSymbolToCache(output, Regs[32], NULL);
                panic++;
            };

            if (strcmp(str, "IOBSD") == 0)
            {
                sprintf(output, "__ZN9IOService15publishResourceEPKcP8OSObject");

                fprintf(stderr, "GOT __ZN9IOService15publishResourceEPKcP8OSObject: 0x%llx\n", Regs[32]);
                addSymbolToCache(output, Regs[32], NULL);
                //sprintf(output,"%llx:__ZN9IOService15publishResourceEPKcP8OSObject\n", Regs[32]);
                //	write (jtoolOutFD, output, strlen(output));
            }
            if (strncmp(str, "BSD root: %s,", strlen("BSD root: %s,")) == 0)
            {
                fprintf(stderr, "GOT IOLog! 0x%llx\n", Regs[32]);
                sprintf(output, "_IOLog");
                addSymbolToCache(output, Regs[32], NULL);
                //sprintf(output, "%llx:_IOLog\n", Regs[32]);
                //write (jtoolOutFD, output, strlen(output));
            }
            if (strcmp(str, "#size-cells") == 0)
            {
                fprintf(stderr, "GOT __ZN8OSSymbol17withCStringNoCopyEPKc: 0x%llx\n", Regs[32]);
                //sprintf(output, "%llx:___ZN8OSSymbol17withCStringNoCopyEPKc\n", Regs[32]);
                //write (jtoolOutFD, output, strlen(output));
                addSymbolToCache("__ZN8OSSymbol17withCStringNoCopyEPKc", Regs[32], NULL);
            }
            if (strcmp(str, "-zp") == 0)
            {

                fprintf(stderr, "GOT PE_Parse_boot_argn: 0x%llx\n", Regs[32]);

                addSymbolToCache("_PE_Parse_boot_argn", Regs[32], NULL);
                //	sprintf(output, "%llx:_PE_Parse_boot_argn\n", Regs[32]);
                //	write (jtoolOutFD, output, strlen(output));
            }
            if (strcmp(str, "hw.memsize") == 0)
            {
                fprintf(stderr, "GOT PE_get_default: 0x%llx\n", Regs[32]);
                // sprintf(output, "%llx:_PE_get_default\n", Regs[32]);
                //owrite (jtoolOutFD, output, strlen(output));
                addSymbolToCache("_PE_get_default", Regs[32], NULL);
                //	return (DISASSEMBLE_BREAK);
            }
        }
    }

    // TODO - optimize by prefetching and storing TEXT__CSTRING

    if (Regs[R3] > 0xfffffff000000000)
    {
        char *sect = MachOGetSectionNameContainingAddress(Regs[R3]);
        if (sect && (strcmp(sect, "__TEXT.__cstring") == 0))
        {
            char *str = getPointerToAddr(Regs[3]);
            if (strcmp(str, "vstruct zone") == 0)
            {
                fprintf(stderr, "GOT zinit: 0x%llx\n", Regs[32]);
                addSymbolToCache("_zinit", Regs[32], NULL);
                // sprintf(output, "%llx:_zinit\n", Regs[32]);
                //		write (jtoolOutFD, output, strlen(output));
            }
        }
    }
    if (Regs[R2] > 0xfffffff000000000)
    {
        char *sect = MachOGetSectionNameContainingAddress(Regs[2]);
        if (sect && (strcmp(sect, "__TEXT.__cstring") == 0))
        {
            char *str = getPointerToAddr(Regs[2]);

            if (strcmp(str, "Jettisoning kext bootstrap segments.") == 0)
            {
                printf("GOT OSKextLog: 0x%llx\n", Regs[32]);
                addSymbolToCache("_OSKextLog", Regs[32], NULL);

                //return DISASSEMBLE_BREAK;
            }
        }
    }
    if (Regs[R1] > 0xfffffff000000000)
    {

        char *sect = MachOGetSectionNameContainingAddress(Regs[1]);
        if (sect && (strcmp(sect, "__TEXT.__cstring") == 0))
        {
            char *str = getPointerToAddr(Regs[1]);

            if (strcmp(str, "OSMalloc_tag") == 0)
            {
                fprintf(stderr, "GOT lck_grp_alloc_init: 0x%llx\n", Regs[32]);
                // sprintf(output,"%llx:_lck_grp_alloc_init\n", Regs[32]);
                //		write (jtoolOutFD, output, strlen(output));
                addSymbolToCache("_lck_grp_alloc_init", Regs[32], NULL);
            }

            if (strcmp(str, "vm_swap_data") == 0)
            {
                fprintf(stderr, "GOT lck_grp_init: 0x%llx\n", Regs[32]);
                addSymbolToCache("_lck_grp_init", Regs[32], NULL);
                //	sprintf(output,"%llx:_lck_grp_init\n", Regs[32]);
                //	write (jtoolOutFD, output, strlen(output));
            }
        }
    }

    return 0;
}

// From Machlib's CS
void doSignature(void *Blob, int ShowEnt, unsigned char *MachOHeader){};
void *dumpBlob(unsigned char *blob, int ShowEnt, unsigned char *MachO){};
int validateBlob(unsigned char *Blob, unsigned int Size, void *SuperBlob){};

#

char *syscall_names[] = {"syscall", "exit", "fork", "read", "write", "open", "close", "wait4", "8  old creat", "link", "unlink", "11  old execv", "chdir", "fchdir", "mknod", "chmod", "chown", "17  old break", "getfsstat", "19  old lseek", "getpid", "21  old mount", "22  old umount", "setuid", "getuid", "geteuid", "ptrace", "recvmsg", "sendmsg", "recvfrom", "accept", "getpeername", "getsockname", "access", "chflags", "fchflags", "sync", "kill", "38  old stat", "getppid", "40  old lstat", "dup", "pipe", "getegid", "profil", "45  old ktrace", "sigaction", "getgid", "sigprocmask", "getlogin", "setlogin", "acct", "sigpending", "sigaltstack", "ioctl", "reboot", "revoke", "symlink", "readlink", "execve", "umask", "chroot", "62  old fstat", "63  used internally , reserved", "64  old getpagesize", "msync", "vfork", "67  old vread", "68  old vwrite", "69  old sbrk", "70  old sstk", "71  old mmap", "72  old vadvise", "munmap", "mprotect", "madvise", "76  old vhangup", "77  old vlimit", "mincore", "getgroups", "setgroups", "getpgrp", "setpgid", "setitimer", "84  old wait", "swapon", "getitimer", "87  old gethostname", "88  old sethostname", "getdtablesize", "dup2", "91  old getdopt", "fcntl", "select", "94  old setdopt", "fsync", "setpriority", "socket", "connect", "99  old accept", "getpriority", "101  old send", "102  old recv", "103  old sigreturn", "bind", "setsockopt", "listen", "107  old vtimes", "108  old sigvec", "109  old sigblock", "110  old sigsetmask", "sigsuspend", "112  old sigstack", "113  old recvmsg", "114  old sendmsg", "115  old vtrace", "gettimeofday", "getrusage", "getsockopt", "119  old resuba", "readv", "writev", "settimeofday", "fchown", "fchmod", "125  old recvfrom", "setreuid", "setregid", "rename", "129  old truncate", "130  old ftruncate", "flock", "mkfifo", "sendto", "shutdown", "socketpair", "mkdir", "rmdir", "utimes", "futimes", "adjtime", "141  old getpeername", "gethostuuid", "143  old sethostid", "144  old getrlimit", "145  old setrlimit", "146  old killpg", "setsid", "148  old setquota", "149  old qquota", "150  old getsockname", "getpgid", "setprivexec", "pread", "pwrite", "nfssvc", "156  old getdirentries", "statfs", "fstatfs", "unmount", "160  old async_daemon", "getfh", "162  old getdomainname", "163  old setdomainname", "164", "quotactl", "166  old exportfs", "mount", "168  old ustat", "csops", "csops_audittoken", "171  old wait3", "172  old rpause", "waitid", "174  old getdents", "175  old gc_control", "add_profil", "kdebug_typefilter", "kdebug_trace_string", "kdebug_trace64", "kdebug_trace", "setgid", "setegid", "seteuid", "sigreturn", "chud", "186", "fdatasync", "stat", "fstat", "lstat", "pathconf", "fpathconf", "193", "getrlimit", "setrlimit", "getdirentries", "mmap", "198  __syscall", "lseek", "truncate", "ftruncate", "__sysctl", "mlock", "munlock", "undelete", "ATsocket", "ATgetmsg", "ATputmsg", "ATPsndreq", "ATPsndrsp", "ATPgetreq", "ATPgetrsp", "213  Reserved for AppleTalk", "214", "215", "mkcomplex", "statv", "lstatv", "fstatv", "getattrlist", "setattrlist", "getdirentriesattr", "exchangedata", "224  old checkuseraccess / fsgetpath ( which moved to 427 )", "searchfs", "delete", "copyfile", "fgetattrlist", "fsetattrlist", "poll", "watchevent", "waitevent", "modwatch", "getxattr", "fgetxattr", "setxattr", "fsetxattr", "removexattr", "fremovexattr", "listxattr", "flistxattr", "fsctl", "initgroups", "posix_spawn", "ffsctl", "246", "nfsclnt", "fhopen", "249", "minherit", "semsys", "msgsys", "shmsys", "semctl", "semget", "semop", "257", "msgctl", "msgget", "msgsnd", "msgrcv", "shmat", "shmctl", "shmdt", "shmget", "shm_open", "shm_unlink", "sem_open", "sem_close", "sem_unlink", "sem_wait", "sem_trywait", "sem_post", "sem_getvalue", "sem_init", "sem_destroy", "open_extended", "umask_extended", "stat_extended", "lstat_extended", "fstat_extended", "chmod_extended", "fchmod_extended", "access_extended", "settid", "gettid", "setsgroups", "getsgroups", "setwgroups", "getwgroups", "mkfifo_extended", "mkdir_extended", "identitysvc", "shared_region_check_np", "shared_region_map_np", "vm_pressure_monitor", "psynch_rw_longrdlock", "psynch_rw_yieldwrlock", "psynch_rw_downgrade", "psynch_rw_upgrade", "psynch_mutexwait", "psynch_mutexdrop", "psynch_cvbroad", "psynch_cvsignal", "psynch_cvwait", "psynch_rw_rdlock", "psynch_rw_wrlock", "psynch_rw_unlock", "psynch_rw_unlock2", "getsid", "settid_with_pid", "psynch_cvclrprepost", "aio_fsync", "aio_return", "aio_suspend", "aio_cancel", "aio_error", "aio_read", "aio_write", "lio_listio", "321  old __pthread_cond_wait", "iopolicysys", "process_policy", "mlockall", "munlockall", "326", "issetugid", "__pthread_kill", "__pthread_sigmask", "__sigwait", "__disable_threadsignal", "__pthread_markcancel", "__pthread_canceled", "__semwait_signal", "335  old utrace", "proc_info", "sendfile", "stat64", "fstat64", "lstat64", "stat64_extended", "lstat64_extended", "fstat64_extended", "getdirentries64", "statfs64", "fstatfs64", "getfsstat64", "__pthread_chdir", "__pthread_fchdir", "audit", "auditon", "352", "getauid", "setauid", "getaudit", "setaudit", "getaudit_addr", "setaudit_addr", "auditctl", "bsdthread_create", "bsdthread_terminate", "kqueue", "kevent", "lchown", "stack_snapshot", "bsdthread_register", "workq_open", "workq_kernreturn", "kevent64", "__old_semwait_signal", "__old_semwait_signal_nocancel", "thread_selfid", "ledger", "kevent_qos", "375", "376", "377", "378", "379", "__mac_execve", "__mac_syscall", "__mac_get_file", "__mac_set_file", "__mac_get_link", "__mac_set_link", "__mac_get_proc", "__mac_set_proc", "__mac_get_fd", "__mac_set_fd", "__mac_get_pid", "__mac_get_lcid", "__mac_get_lctx", "__mac_set_lctx", "setlcid", "getlcid", "read_nocancel", "write_nocancel", "open_nocancel", "close_nocancel", "wait4_nocancel", "recvmsg_nocancel", "sendmsg_nocancel", "recvfrom_nocancel", "accept_nocancel", "msync_nocancel", "fcntl_nocancel", "select_nocancel", "fsync_nocancel", "connect_nocancel", "sigsuspend_nocancel", "readv_nocancel", "writev_nocancel", "sendto_nocancel", "pread_nocancel", "pwrite_nocancel", "waitid_nocancel", "poll_nocancel", "msgsnd_nocancel", "msgrcv_nocancel", "sem_wait_nocancel", "aio_suspend_nocancel", "__sigwait_nocancel", "__semwait_signal_nocancel", "__mac_mount", "__mac_get_mount", "__mac_getfsstat", "fsgetpath", "audit_session_self", "audit_session_join", "fileport_makeport", "fileport_makefd", "audit_session_port", "pid_suspend", "pid_resume", "pid_hibernate", "pid_shutdown_sockets", "437  old shared_region_slide_np", "shared_region_map_and_slide_np",
                         "kas_info", "memorystatus_control", "guarded_open_np", "guarded_close_np",
                         "guarded_kqueue_np",
                         "change_fdguard_np",
                         "proc_rlimit_control",
                         "proc_rlimit_control",
                         "proc_connectx",
                         "proc_disconnectx",
                         "proc_peeloff",
                         "proc_socket_delegate",
                         "proc_telemetry",
                         "proc_uuid_policy",       // 452
                         "memorystatus_get_level", // 453
                         "system_override",        // 454 - as of iOS8
                         "vfs_purge",
                         "sfi_ctl",
                         "sfi_pidctl",
                         "coalition",
                         "coalition_info",
                         "necp_match_policy", // 460
                         "getattrlistbulk",   // 461
                         "clonefileat",       // 462
                         "openat",
                         "openat_nocancel",
                         "renameat",
                         "faccessat",
                         "fchmodat",
                         "fchownat",
                         "fstatat",
                         "fstatat64", // 470
                         "linkat",
                         "unlinkat", // 472
                         "readlinkat",
                         "symlinkat",
                         "mkdirat",
                         "getattrlistat",
                         "proc_trace_log",
                         "bsdthread_ctl",
                         "openbyid_np",
                         "recvmsg_x", // 480
                         "sendmsg_x",
                         "thread_selfusage",
                         "csrctl",
                         "guarded_open_dprotected_np",
                         "guarded_write_np",
                         "guarded_pwrite_np",
                         "guarded_writev_np",
                         "rename_ext",
                         "mremap_encrypted",
                         // iOS 9/Xnu 3216
                         "netagent_trigger", // 490
                         "stack_snapshot_with_config",
                         "microstackshot",
                         "grab_pgo_data",
                         "persona",
                         "#495",
                         "#496",
                         "#497",
                         "#498",
                         "work_interval_ctl",
                         "getentropy    ",
                         "necp_open     ",
                         "necp_client_action",
                         "__nexus_open  ",
                         "__nexus_register",
                         "__nexus_deregister",
                         "__nexus_create",
                         "__nexus_destroy",
                         "__nexus_get_opt",
                         "__nexus_set_opt",
                         "__channel_open",
                         "__channel_get_info",
                         "__channel_sync",
                         "__channel_get_opt",
                         "__channel_set_opt",
                         "ulock_wait    ",
                         "ulock_wake    ",
                         "fclonefileat  ",
                         "fs_snapshot   ",
                         "#519",
                         "terminate_with_payload",
                         "abort_with_payload",
                         NULL

};

// That MOV PC,R9 always gives it away , now..
const char *ARMExcVector = "\x09\xf0\xa0\xe1\xfe\xff\xff\xea";

const char *mach_syscall_name_table[128] = {
    /* 0 */ "kern_invalid",
    /* 1 */ "kern_invalid",
    /* 2 */ "kern_invalid",
    /* 3 */ "kern_invalid",
    /* 4 */ "kern_invalid",
    /* 5 */ "kern_invalid",
    /* 6 */ "kern_invalid",
    /* 7 */ "kern_invalid",
    /* 8 */ "kern_invalid",
    /* 9 */ "kern_invalid",
    /* 10 */ "_kernelrpc_mach_vm_allocate_trap",         // OS X : "kern_invalid",
    /* 11 */ "_kernelrpc_vm_allocate_trap",              // OS X : "kern_invalid",
    /* 12 */ "_kernelrpc_mach_vm_deallocate_trap",       // OS X: "kern_invalid",
    /* 13 */ "_kernelrpc_vm_deallocate_trap",            // "kern_invalid",
    /* 14 */ "_kernelrpc_mach_vm_protect_trap",          //"kern_invalid",
    /* 15 */ "_kernelrpc_vm_protect_trap",               // kern_invalid",
    /* 16 */ "_kernelrpc_mach_port_allocate_trap",       //"kern_invalid",
    /* 17 */ "_kernelrpc_mach_port_destroy_trap",        //"kern_invalid",
    /* 18 */ "_kernelrpc_mach_port_deallocate_trap",     // "kern_invalid",
    /* 19 */ "_kernelrpc_mach_port_mod_refs_trap",       //"kern_invalid",
    /* 20 */ "_kernelrpc_mach_port_move_member_trap",    //"kern_invalid",
    /* 21 */ "_kernelrpc_mach_port_insert_right_trap",   //"kern_invalid",
    /* 22 */ "_kernelrpc_mach_port_insert_member_trap",  // "kern_invalid",
    /* 23 */ "_kernelrpc_mach_port_extract_member_trap", // "kern_invalid",
    /* 24 */ "__kernelrpc_mach_port_construct_trap",     // in 24xx, else "kern_invalid",
    /* 25 */ "__kernelrpc_mach_port_destruct_trap",      // in 24xx, "kern_invalid",
    /* 26 */ "mach_reply_port",
    /* 27 */ "thread_self_trap",
    /* 28 */ "task_self_trap",
    /* 29 */ "host_self_trap",
    /* 30 */ "kern_invalid",
    /* 31 */ "mach_msg_trap",
    /* 32 */ "mach_msg_overwrite_trap",
    /* 33 */ "semaphore_signal_trap",
    /* 34 */ "semaphore_signal_all_trap",
    /* 35 */ "semaphore_signal_thread_trap",
    /* 36 */ "semaphore_wait_trap",
    /* 37 */ "semaphore_wait_signal_trap",
    /* 38 */ "semaphore_timedwait_trap",
    /* 39 */ "semaphore_timedwait_signal_trap",
    /* 40 */ "kern_invalid",
    /* 41 */ "__kernelrpc_mach_port_guard_trap",   // as of 24xx - else "kern_invalid",
    /* 42 */ "__kernelrpc_mach_port_unguard_trap", // as of 24xx - else "kern_invalid",
    /* 43 */ "map_fd",                             // invalidated in 27xx
    /* 44 */ "task_name_for_pid",
    /* 45 */ "task_for_pid",
    /* 46 */ "pid_for_task",
    /* 47 */ "kern_invalid",
    /* 48 */ "macx_swapon",
    /* 49 */ "macx_swapoff",
    /* 50 */ "kern_invalid",
    /* 51 */ "macx_triggers",
    /* 52 */ "macx_backing_store_suspend",
    /* 53 */ "macx_backing_store_recovery",
    /* 54 */ "kern_invalid",
    /* 55 */ "kern_invalid",
    /* 56 */ "kern_invalid",
    /* 57 */ "kern_invalid",
    /* 58 */ "pfz_exit",
    /* 59 */ "swtch_pri",
    /* 60 */ "swtch",
    /* 61 */ "thread_switch",
    /* 62 */ "clock_sleep_trap",
    /* 63 */ "kern_invalid",
    /* traps 64 - 95 reserved (debo) */
    /* 64 */ "kern_invalid",
    /* 65 */ "kern_invalid",
    /* 66 */ "kern_invalid",
    /* 67 */ "kern_invalid",
    /* 68 */ "kern_invalid",
    /* 69 */ "kern_invalid",
    /* 70 */ "kern_invalid",
    /* 71 */ "kern_invalid",
    /* 72 */ "kern_invalid",
    /* 73 */ "kern_invalid",
    /* 74 */ "kern_invalid",
    /* 75 */ "kern_invalid",
    /* 76 */ "kern_invalid",
    /* 77 */ "kern_invalid",
    /* 78 */ "kern_invalid",
    /* 79 */ "kern_invalid",
    /* 80 */ "kern_invalid",
    /* 81 */ "kern_invalid",
    /* 82 */ "kern_invalid",
    /* 83 */ "kern_invalid",
    /* 84 */ "kern_invalid",
    /* 85 */ "kern_invalid",
    /* 86 */ "kern_invalid",
    /* 87 */ "kern_invalid",
    /* 88 */ "kern_invalid",
    /* 89 */ "mach_timebase_info_trap",
    /* 90 */ "mach_wait_until_trap",
    /* 91 */ "mk_timer_create_trap",
    /* 92 */ "mk_timer_destroy_trap",
    /* 93 */ "mk_timer_arm_trap",
    /* 94 */ "mk_timer_cancel_trap",
    /* 95 */ "kern_invalid",
    /* traps 64 - 95 reserved (debo) */
    /* 96 */ "kern_invalid",
    /* 97 */ "kern_invalid",
    /* 98 */ "kern_invalid",
    /* 99 */ "kern_invalid",
    /* traps 100-107 reserved for iokit (esb) */
    /* 100 */ "iokit_user_client_trap",
    /* 101 */ "kern_invalid",
    /* 102 */ "kern_invalid",
    /* 103 */ "kern_invalid",
    /* 104 */ "kern_invalid",
    /* 105 */ "kern_invalid",
    /* 106 */ "kern_invalid",
    /* 107 */ "kern_invalid",
    /* traps 108-127 unused */
    /* 108 */ "kern_invalid",
    /* 109 */ "kern_invalid",
    /* 110 */ "kern_invalid",
    /* 111 */ "kern_invalid",
    /* 112 */ "kern_invalid",
    /* 113 */ "kern_invalid",
    /* 114 */ "kern_invalid",
    /* 115 */ "kern_invalid",
    /* 116 */ "kern_invalid",
    /* 117 */ "kern_invalid",
    /* 118 */ "kern_invalid",
    /* 119 */ "kern_invalid",
    /* 120 */ "kern_invalid",
    /* 121 */ "kern_invalid",
    /* 122 */ "kern_invalid",
    /* 123 */ "kern_invalid",
    /* 124 */ "kern_invalid",
    /* 125 */ "kern_invalid",
    /* 126 */ "kern_invalid",
    /* 127 */ "kern_invalid",
};

// Fixed this because as of iOS 9 or so Apple moved source cache to
// /Library/Caches/com.apple.xbs/Sources/xnu/xnu-3216.0.0.1.15

#define XNUSIG "/xnu-"

#define SYS_MAXSYSCALL 443
#define SYS_MAXSYSCALL_7 454
#define SYS_MAXSYSCALL_8 489
#define SYS_MAXSYSCALL_9 500
#define SYS_MAXSYSCALL_10 521

#define SIG1 "\x00\x00\x00\x00" \
             "\x00\x00\x00\x00" \
             "\x01\x00\x00\x00" \
             "\x00\x00\x00\x00" \
             "\x01\x00\x00\x00"

#define SIG1_SUF "\x00\x00\x00\x00" \
                 "\x00\x00\x00\x00" \
                 "\x00\x00\x00\x00" \
                 "\x04\x00\x00\x00"

#define SIG2 "\x00\x00\x00\x00" \
             "\x00\x00\x00\x00" \
             "\x01\x00\x00\x00" \
             "\x1C\x00\x00\x00" \
             "\x00\x00\x00\x00"

#define SIG1_IOS7X "\x00\x00\x00\x00" \
                   "\x00\x00\x00\x00" \
                   "\x01\x00\x00\x00" \
                   "\x00\x00\x00\x00"
#define SIG2_IOS7X "\x00\x00\x00\x00" \
                   "\x00\x00\x00\x00" \
                   "\x00\x00\x00\x00" \
                   "\x01\x00\x04\x00"

#define SIG1_IOS8X "\x00\x00\x00\x00\x01\x00\x04\x00"

#define SIG1_AFTER_0x18_IOS8X "\x06\x00\x00\x00" \
                              "\x03\x00\x0c\x00"

#define SIG_SYSCALL_3 "\x06\x00\x00\x00\x03\x00\x0c\x00"

#define SIG_MIG_MACH_VM "\xC0\x12\x00\x00\xD4\x12\x00\x00"
#define SIG_MIG_TASK "\x48\x0d\x00\x00\x72\x0d\x00\x00"

typedef struct mig_subsystem_struct
{
    uint32_t min;
    uint32_t max;
    char *names;
} mig_subsys;

mig_subsys mach_vm_subsys = {0x12c0, 0x12d4, NULL};
mig_subsys task_subsys = {0xd48, 0xd7a, NULL};
mig_subsys mach_host_subsys_9 = {200, 230};
mig_subsys host_priv_subsys = {400, 426};
mig_subsys thread_act_subsys = {3600, 3628};
mig_subsys mach_port_subsys = {3200, 3236};
mig_subsys is_iokit_subsys = {2800, 2885};
mig_subsys is_iokit_subsys_9 = {2800, 2885};
mig_subsys processor_set_subsys = {4000, 4010};
mig_subsys host_security_subsys = {600, 602};
mig_subsys processor_subsys = {3000, 3006};

// It would be great if we could just get the _subsystem_to_name_map ... mig generated defines,
// but the iOS compiler complains. So no.

typedef struct mig_func_struct
{
    char *name;
    int num;
} mig_func_desc;

mig_func_desc processor_mig[] = {

    {"processor_start", 3000},
    {"processor_exit", 3001},
    {"processor_info", 3002},
    {"processor_control", 3003},
    {"processor_assign", 3004},
    {"processor_get_assignment", 3005},
    {NULL, 3006}};
mig_func_desc mach_port_mig[] = {{"mach_port_names", 3200}, {"mach_port_type", 3201}, {"mach_port_rename", 3202}, {"mach_port_allocate_name", 3203}, {"mach_port_allocate", 3204}, {"mach_port_destroy", 3205}, {"mach_port_deallocate", 3206}, {"mach_port_get_refs", 3207}, {"mach_port_mod_refs", 3208}, {"mach_port_peek", 3209}, {"mach_port_set_mscount", 3210}, {"mach_port_get_set_status", 3211}, {"mach_port_move_member", 3212}, {"mach_port_request_notification", 3213}, {"mach_port_insert_right", 3214}, {"mach_port_extract_right", 3215}, {"mach_port_set_seqno", 3216}, {"mach_port_get_attributes", 3217}, {"mach_port_set_attributes", 3218}, {"mach_port_allocate_qos", 3219}, {"mach_port_allocate_full", 3220}, {"task_set_port_space", 3221}, {"mach_port_get_srights", 3222}, {"mach_port_space_info", 3223}, {"mach_port_dnrequest_info", 3224}, {"mach_port_kernel_object", 3225}, {"mach_port_insert_member", 3226}, {"mach_port_extract_member", 3227}, {"mach_port_get_context", 3228}, {"mach_port_set_context", 3229}, {"mach_port_kobject", 3230}, {"mach_port_construct", 3231}, {"mach_port_destruct", 3232}, {"mach_port_guard", 3233}, {"mach_port_unguard", 3234}, {"mach_port_space_basic_info", 3235}, {((void *)0), 3236}};

mig_func_desc host_security_mig[] = {{"host_security_create_task_token", 600},
                                     {"host_security_set_task_token", 601},
                                     {NULL, 602}};

mig_func_desc processor_set_mig[] = {
    {"processor_set_statistics", 4000},
    {"processor_set_destroy", 4001},
    {"processor_set_max_priority", 4002},
    {"processor_set_policy_enable", 4003},
    {"processor_set_policy_disable", 4004},
    {"processor_set_tasks", 4005},
    {"processor_set_threads", 4006},
    {"processor_set_policy_control", 4007},
    {"processor_set_stack_usage", 4008},
    {"processor_set_info", 4009},
    {NULL, 4010}};

mig_func_desc iokit_mig[] = {
    {"io_object_get_class", 2800},
    {"io_object_conforms_to", 2801},
    {"io_iterator_next", 2802},
    {"io_iterator_reset", 2803},
    {"io_service_get_matching_services", 2804},
    {"io_registry_entry_get_property", 2805},
    {"io_registry_create_iterator", 2806},
    {"io_registry_iterator_enter_entry", 2807},
    {"io_registry_iterator_exit_entry", 2808},
    {"io_registry_entry_from_path", 2809},
    {"io_registry_entry_get_name", 2810},
    {"io_registry_entry_get_properties", 2811},
    {"io_registry_entry_get_property_bytes", 2812},
    {"io_registry_entry_get_child_iterator", 2813},
    {"io_registry_entry_get_parent_iterator", 2814},
    {"io_service_close", 2816},
    {"io_connect_get_service", 2817},
    {"io_connect_set_notification_port", 2818},
    {"io_connect_map_memory", 2819},
    {"io_connect_add_client", 2820},
    {"io_connect_set_properties", 2821},
    {"io_connect_method_scalarI_scalarO", 2822},
    {"io_connect_method_scalarI_structureO", 2823},
    {"io_connect_method_scalarI_structureI", 2824},
    {"io_connect_method_structureI_structureO", 2825},
    {"io_registry_entry_get_path", 2826},
    {"io_registry_get_root_entry", 2827},
    {"io_registry_entry_set_properties", 2828},
    {"io_registry_entry_in_plane", 2829},
    {"io_object_get_retain_count", 2830},
    {"io_service_get_busy_state", 2831},
    {"io_service_wait_quiet", 2832},
    {"io_registry_entry_create_iterator", 2833},
    {"io_iterator_is_valid", 2834},
    {"io_catalog_send_data", 2836},
    {"io_catalog_terminate", 2837},
    {"io_catalog_get_data", 2838},
    {"io_catalog_get_gen_count", 2839},
    {"io_catalog_module_loaded", 2840},
    {"io_catalog_reset", 2841},
    {"io_service_request_probe", 2842},
    {"io_registry_entry_get_name_in_plane", 2843},
    {"io_service_match_property_table", 2844},
    {"io_async_method_scalarI_scalarO", 2845},
    {"io_async_method_scalarI_structureO", 2846},
    {"io_async_method_scalarI_structureI", 2847},
    {"io_async_method_structureI_structureO", 2848},
    {"io_service_add_notification", 2849},
    {"io_service_add_interest_notification", 2850},
    {"io_service_acknowledge_notification", 2851},
    {"io_connect_get_notification_semaphore", 2852},
    {"io_connect_unmap_memory", 2853},
    {"io_registry_entry_get_location_in_plane", 2854},
    {"io_registry_entry_get_property_recursively", 2855},
    {"io_service_get_state", 2856},
    {"io_service_get_matching_services_ool", 2857},
    {"io_service_match_property_table_ool", 2858},
    {"io_service_add_notification_ool", 2859},
    {"io_object_get_superclass", 2860},
    {"io_object_get_bundle_identifier", 2861},
    {"io_service_open_extended", 2862},
    {"io_connect_map_memory_into_task", 2863},
    {"io_connect_unmap_memory_from_task", 2864},
    {"io_connect_method", 2865},
    {"io_connect_async_method", 2866},
    {"io_registry_entry_get_registry_entry_id", 2871},
    {"io_connect_method_var_output", 2872},
    {"io_service_get_matching_service", 2873},
    {"io_service_get_matching_service_ool", 2874},
    {"io_service_get_authorization_id", 2875},
    {"io_service_set_authorization_id", 2876},
    {"io_server_version", 2877},
    {"io_registry_entry_get_properties_bin", 2878},
    {"io_registry_entry_get_property_bin", 2879},
    {"io_service_get_matching_service_bin", 2880},
    {"io_service_get_matching_services_bin", 2881},
    {"io_service_match_property_table_bin", 2882},
    {"io_service_add_notification_bin", 2883},
    {"io_registry_entry_get_path_ool", 2884},
    {"io_registry_entry_from_path_ool", 2885},

    {NULL, 2886}};

mig_func_desc mach_vm_mig[] = {
    {"mach_vm_allocate", 4800},
    {"mach_vm_deallocate", 4801},
    {"mach_vm_protect", 4802},
    {"mach_vm_inherit", 4803},
    {"mach_vm_read", 4804},
    {"mach_vm_read_list", 4805},
    {"mach_vm_write", 4806},
    {"mach_vm_copy", 4807},
    {"mach_vm_read_overwrite", 4808},
    {"mach_vm_msync", 4809},
    {"mach_vm_behavior_set", 4810},
    {"mach_vm_map", 4811},
    {"mach_vm_machine_attribute", 4812},
    {"mach_vm_remap", 4813},
    {"mach_vm_page_query", 4814},
    {"mach_vm_region_recurse", 4815},
    {"mach_vm_region", 4816},
    {"_mach_make_memory_entry", 4817},
    {"mach_vm_purgable_control", 4818},
    {"mach_vm_page_info", 4819},
    {NULL, 4820}};

mig_func_desc mach_host_mig[] = {{"host_info", 200}, {"host_kernel_version", 201}, {"_host_page_size", 202}, {"mach_memory_object_memory_entry", 203}, {"host_processor_info", 204}, {"host_get_io_master", 205}, {"host_get_clock_service", 206}, {"kmod_get_info", 207}, {"host_zone_info", 208}, {"host_virtual_physical_table_info", 209}, {"processor_set_default", 213}, {"processor_set_create", 214}, {"mach_memory_object_memory_entry_64", 215}, {"host_statistics", 216}, {"host_request_notification", 217}, {"host_lockgroup_info", 218}, {"host_statistics64", 219}, {"mach_zone_info", 220}, {"host_create_mach_voucher", 222}, {"host_register_mach_voucher_attr_manager", 223}, {"host_register_well_known_mach_voucher_attr_manager", 224},

                                 {"host_set_atm_diagnostic_flag", 225},
                                 {"host_get_atm_diagnostic_flag", 226},
                                 {"mach_memory_info", 227},
                                 {"host_set_multiuser_config_flags", 228},
                                 {"host_get_multiuser_config_flags", 229},
                                 {"host_check_multiuser_mode", 230}

                                 ,
                                 {((void *)0), 231}};

mig_func_desc task_mig[] = {{"task_create", 3400}, {"task_terminate", 3401}, {"task_threads", 3402}, {"mach_ports_register", 3403}, {"mach_ports_lookup", 3404}, {"task_info", 3405}, {"task_set_info", 3406}, {"task_suspend", 3407}, {"task_resume", 3408}, {"task_get_special_port", 3409}, {"task_set_special_port", 3410}, {"thread_create", 3411}, {"thread_create_running", 3412}, {"task_set_exception_ports", 3413}, {"task_get_exception_ports", 3414}, {"task_swap_exception_ports", 3415}, {"lock_set_create", 3416}, {"lock_set_destroy", 3417}, {"semaphore_create", 3418}, {"semaphore_destroy", 3419}, {"task_policy_set", 3420}, {"task_policy_get", 3421}, {"task_sample", 3422}, {"task_policy", 3423}, {"task_set_emulation", 3424}, {"task_get_emulation_vector", 3425}, {"task_set_emulation_vector", 3426}, {"task_set_ras_pc", 3427}, {"task_zone_info", 3428}, {"task_assign", 3429}, {"task_assign_default", 3430}, {"task_get_assignment", 3431}, {"task_set_policy", 3432}, {"task_get_state", 3433}, {"task_set_state", 3434}, {"task_set_phys_footprint_limit", 3435}, {"task_suspend2", 3436}, {"task_resume2", 3437}, {"task_purgable_info", 3438}, {"task_get_mach_voucher", 3439}, {"task_set_mach_voucher", 3440}, {"task_swap_mach_voucher", 3441}, {"task_generate_corpse", 3442}, {"task_map_corpse_info", 3443}, {"task_register_dyld_image_infos", 3444}, {"task_unregister_dyld_image_infos", 3445}, {"task_get_dyld_image_infos", 3446}, {"task_register_dyld_shared_cache_image_info", 3447}, {"task_register_dyld_set_dyld_state", 3448}, {"task_register_dyld_get_process_state", 3449}, {"task_map_corpse_info_64", 3450},

                            {((void *)0), 3451}};

mig_func_desc host_priv_mig[] = {
    {"host_get_boot_info", 400},
    {"host_reboot", 401},
    {"host_priv_statistics", 402},
    {"host_default_memory_manager", 403},
    {"vm_wire", 404},
    {"thread_wire", 405},
    {"vm_allocate_cpm", 406},
    {"host_processors", 407},
    {"host_get_clock_control", 408},
    {"kmod_create", 409},
    {"kmod_destroy", 410},
    {"kmod_control", 411},
    {"host_get_special_port", 412},
    {"host_set_special_port", 413},
    {"host_set_exception_ports", 414},
    {"host_get_exception_ports", 415},
    {"host_swap_exception_ports", 416},
    {"mach_vm_wire", 418},
    {"host_processor_sets", 419},
    {"host_processor_set_priv", 420},
    {"set_dp_control_port", 421},
    {"get_dp_control_port", 422},
    {"host_set_UNDServer", 423},
    {"host_get_UNDServer", 424},
    {"kext_request", 425},
    {NULL, 426}};

//mig_func_desc thread_act_mig [] = { subsystem_to_name_map_thread_act , { NULL, -1}};
mig_func_desc thread_act_mig[] = {{"thread_terminate", 3600}, {"act_get_state", 3601}, {"act_set_state", 3602}, {"thread_get_state", 3603}, {"thread_set_state", 3604}, {"thread_suspend", 3605}, {"thread_resume", 3606}, {"thread_abort", 3607}, {"thread_abort_safely", 3608}, {"thread_depress_abort", 3609}, {"thread_get_special_port", 3610}, {"thread_set_special_port", 3611}, {"thread_info", 3612}, {"thread_set_exception_ports", 3613}, {"thread_get_exception_ports", 3614}, {"thread_swap_exception_ports", 3615}, {"thread_policy", 3616}, {"thread_policy_set", 3617}, {"thread_policy_get", 3618}, {"thread_sample", 3619}, {"etap_trace_thread", 3620}, {"thread_assign", 3621}, {"thread_assign_default", 3622}, {"thread_get_assignment", 3623}, {"thread_set_policy", 3624}, {"thread_get_mach_voucher", 3625}, {"thread_set_mach_voucher", 3626}, {"thread_swap_mach_voucher", 3627}, {((void *)0), 3628}};

void dumpMIGSubsystem(mig_subsys *Subsys,
                      mig_subsys *OurSubSys,
                      int is64)
{

    // Behind us is the server routine
    char *func = (char *)((char *)(Subsys)-is64 ? 8 : 4);

    uint64_t routineAddr;
    uint64_t *routinePtr;

    //  if (is64) { serverRoutineAddr =  *((uint64_t *) func); }
    // else { serverRoutineAddr =  *((uint64_t *) func); }

    mig_func_desc *mig_subsystem_dumped;

    if (Subsys->min == processor_mig[0].num)
    {
        mig_subsystem_dumped = processor_mig;
    };
    if (Subsys->min == processor_set_mig[0].num)
    {
        mig_subsystem_dumped = processor_set_mig;
    };
    if (Subsys->min == host_security_mig[0].num)
    {
        mig_subsystem_dumped = host_security_mig;
    };
    if (Subsys->min == iokit_mig[0].num)
    {
        mig_subsystem_dumped = iokit_mig;
    };
    if (Subsys->min == mach_port_mig[0].num)
    {
        mig_subsystem_dumped = mach_port_mig;
    };
    if (Subsys->min == mach_vm_mig[0].num)
    {
        mig_subsystem_dumped = mach_vm_mig;
    };
    if (Subsys->min == mach_host_mig[0].num)
    {
        mig_subsystem_dumped = mach_host_mig;
    };
    if (Subsys->min == host_priv_mig[0].num)
    {
        mig_subsystem_dumped = host_priv_mig;
    };
    if (Subsys->min == task_mig[0].num)
    {
        mig_subsystem_dumped = task_mig;
    };
    if (Subsys->min == thread_act_mig[0].num)
    {
        mig_subsystem_dumped = thread_act_mig;
    };

    if (mig_subsystem_dumped)
    {
        int f = 0;
        int adv = (is64 ? 8 : 4);
        routinePtr = (char *)Subsys + ((is64 ? 4 : 5) * adv);

        int last = OurSubSys->max;

        // printf("Max is %d , last is %d\n", Subsys->max, last);

        // last -  Subsys->min - 1);
        if (last > Subsys->max)
            last = Subsys->max;

        while (mig_subsystem_dumped[f].num < last) //

        //	while (mig_subsystem_dumped[f].num > -1)
        {
            if (is64)
                routineAddr = *routinePtr;
            else
            {
                routineAddr = *((uint32_t *)routinePtr);
            }

            if (wantJToolOut)
            {
                char output[1024];
                //			sprintf(output,"0x%llx:__X%s\n", routineAddr, mig_subsystem_dumped[f].name);
                sprintf(output, "__X%s", mig_subsystem_dumped[f].name);
                addSymbolToCache(output, routineAddr, "");

                //		write (jtoolOutFD, output, strlen(output));
            }
            else
                printf("\t__X%s: 0x%llx (%d)\n", mig_subsystem_dumped[f].name, routineAddr, mig_subsystem_dumped[f].num);

            f++;
            int skip = mig_subsystem_dumped[f].num - mig_subsystem_dumped[f - 1].num;
            routinePtr = ((char *)routinePtr) + ((is64 ? 5 : 6) * skip * adv);
        }

        // If the last num we got to is not the subsystem's max, warn
        if (last < Subsys->max - 1)
        {
            printf("\tWarning: This kernel is newer than joker is (%d < %d)!\n",
                   last, Subsys->max - 1);
        }
    }
    else
    {
        printf("Unknown MIG system (%d-%d)\n", Subsys->min, Subsys->max);
    }

} // dumpMIG

void dumpMachTraps(char *mach, int is64)
{
    int i;
    int thumb = 0;
    uint64_t kernInvalid = *((uint64_t *)mach);
    if (!is64)
        kernInvalid = *((uint32_t *)mach);

    if (mach)
        printf("Kern invalid should be %llx. Ignoring those\n", kernInvalid);
    ;

    for (i = 0; i < 128; i++)
    {
        uint64_t addr = *((int64_t *)(mach + 4 * 8 * i));
        uint32_t addr32 = *((int *)(mach + 3 * 4 * i));

        if (is64)
        {
        }
        else
        {
            if (addr == *((int *)(mach + 4)))
                continue;
            if ((addr % 4) == 1)
            {
                addr--;
                thumb++;
            }
            if ((addr % 4) == -3)
            {
                addr--;
                thumb++;
            }
            if (addr % 4)
            {
                thumb = "-1";
            }
        }

        if (addr && (addr != kernInvalid))
        {
            if (wantJToolOut)
            {

                char output[1024];

                sprintf(output, "_%s", mach_syscall_name_table[i]);

                addSymbolToCache(output, addr, NULL);

                //	sprintf(output,"%llx:%s:_Mach_Trap_%d\n", addr, mach_syscall_name_table[i], i);
                // write (jtoolOutFD, output, strlen(output));
            }
            else
                printf("%3d %-40s %llx %s\n", i, mach_syscall_name_table[i], is64 ? addr : addr32, (thumb ? "T" : "-"));
        }
        else
        { /* suppress, but also warn if it's not kern_invalid for whatever reason */

            //printf("%llx  Trap #%d should be kern_invalid, but isn't\n", addr, i);
        }

    } // end for < 128 ..

} // dumpMachTraps

int g_Verbose = 0;

char *MachOLookupSymbolAtAddress(uint64_t, unsigned char *File);

extern int disassARMInstr(unsigned char *Loc, uint64_t Address, disassembled_instruction *returned);
extern int disassARM64Instr(uint32_t *Loc, uint64_t Address, disassembled_instruction *returned);
extern int doInstr(disassembled_instruction *Instr, int Print);
uint32_t MachOGetSectionOffset(void *File, char *Name);

int symbolicateKextStubs(char *MMapped, int Size, char *Name, int Split)
{

    // Name only actually used for debugging...

    // @TODO: Could actually locate stub section by flags, rather than hard coded name. Machlib can do that.

    char *splitKext = NULL;
    char *d = getenv("JOKER_DIR");
    if (!d)
        d = "/tmp";

    char buf[1024];
    char filename[1024];
    snprintf(buf, 1024, "%s/%s.kext", d, Name);

    if (Split)
    {
        int fd = open(buf, O_RDWR);
        if (fd < 0)
        {
            fprintf(stderr, "Unable to open %s.. can't symbolicate\n",
                    buf);
            return -1;
        }

        struct stat stbuf;
        int rc = fstat(fd, &stbuf);

        int filesize = stbuf.st_size;

        splitKext = mmap(NULL,
                         filesize,              // size_t len,
                         PROT_READ,             // int prot,
                         MAP_SHARED | MAP_FILE, // int flags,
                         fd,                    // int fd,
                         0);                    // off_t offset);

        //zzzz
        segments = processFile(splitKext, filesize, getKernelCacheArch(), 0, 0, 0);
        if (g_jdebug)
            fprintf(stderr, "This is a split kext.. %d (0x%x) bytes\n", filesize, filesize);
    }

    uint32_t stubs_off = MachOGetSectionOffset((unsigned char *)MMapped, "__TEXT.__stubs");
    uint32_t stubs_size = MachOGetSectionSize((unsigned char *)MMapped, "__TEXT.__stubs");
    uint64_t stubs_addr = MachOGetSectionAddr((unsigned char *)MMapped, "__TEXT.__stubs");

    if (!stubs_size)
    {
        stubs_off = MachOGetSectionOffset((unsigned char *)MMapped, "__TEXT_EXEC.__stubs");
        stubs_size = MachOGetSectionSize((unsigned char *)MMapped, "__TEXT_EXEC.__stubs");
        stubs_addr = MachOGetSectionAddr((unsigned char *)MMapped, "__TEXT_EXEC.__stubs");
    }

    char *oh_my_got = "__DATA.__got";

    uint32_t got_off = MachOGetSectionOffset((unsigned char *)MMapped, oh_my_got);
    uint32_t got_size = MachOGetSectionSize((unsigned char *)MMapped, oh_my_got);
    uint64_t got_addr = MachOGetSectionAddr((unsigned char *)MMapped, oh_my_got);

    if (!got_size)
    {
        oh_my_got = "__DATA_CONST.__got";
        got_off = MachOGetSectionOffset((unsigned char *)MMapped, oh_my_got);
        got_size = MachOGetSectionSize((unsigned char *)MMapped, oh_my_got);
        got_addr = MachOGetSectionAddr((unsigned char *)MMapped, oh_my_got);
    }

    int companionFileFD = 0;

    if (!stubs_size)
    {
        fprintf(stderr, "Unable to find __TEXT.__stubs in kext %s. Won't symbolicate\n", Name);
        return (-1);
    }

    // Otherwise, we're here, and found the stubs. Iterate over stubs section, instruction by instruction,
    // Looking for following pattern:

    // fffffff00405e664        d0000010        ADRP   X16, 2                   ; ->R16 = 0xfffffff004060000
    // fffffff00405e668        f9400210        LDR    X16, [X16, #0]   ; -R16 = *(R16 + 0) =  *(0xfffffff004060000) = 0xfffffff007578748 ... ?..
    // fffffff00405e66c        d61f0200        BR     X16                              ;  0xfffffff007578748

    // And at the BR, attempt to see what it is we are branching to (based on X16's value).
    // We can actually use our disassembly callback here, disassembling three instructions at a time
    // But this shows another usage of machlib

    // register_disassembled_register_call_callback (function_identifier);

    int pos = 0;

    if (g_jdebug)
        fprintf(stderr, "Symbolicating stubs for %s  from off 0x%x\n", Name, stubs_off);
    while (pos < stubs_size)
    {
        // Take the scenic route and actually disassemble the instructions.
        // This is longer, but certainly safer and more accurate should AAPL
        // decide to ever change the format. It would have been simpler to
        // iterate over the stubs themselves (in __DATA.__got) since compiler
        // emits them in corresponding order..

        disassembled_instruction inst1;
        disassembled_instruction inst2;
        disassembled_instruction inst3;

        disassARM64Instr((splitKext ? splitKext : MMapped) + stubs_off + pos, stubs_addr + pos, &inst1);
        disassARM64Instr((splitKext ? splitKext : MMapped) + stubs_off + pos + 4, stubs_addr + pos + 4, &inst2);
        disassARM64Instr((splitKext ? splitKext : MMapped) + stubs_off + pos + 8, stubs_addr + pos + 8, &inst3);

        if (strcmp(inst1.mnemonic, "ADRP") ||
            strcmp(inst2.mnemonic, "LDR") ||
            strcmp(inst3.mnemonic, "BR"))
        {
            fprintf(stderr, "0x%x\n", *((uint32_t *)((splitKext ? splitKext : MMapped) + stubs_off + pos)));

            fprintf(stderr, "Warning: Error in disassembly - got %s,%s,%s..\n",
                    inst1.mnemonic, inst2.mnemonic, inst3.mnemonic);
        }
        else
        {

            // Can't use this just yet. @TODO

            // We can also verify that the registers in all instructions match,
            // (i.e. not necessarily R16, but that we ADRP, LDR and BR to same
            // register. But that's unnecessary at this point.

            //doInstr(&inst1, 0);
            //doInstr(&inst2, 0);
            //doInstr(&inst3, 0);

            uint64_t reg = inst1.immediate;
            uint64_t off = inst2.immediate;

            uint64_t stub = reg + off;

            struct symtabent *sym = NULL;
            // if (g_jdebug)
            char res[1024];

            if (stub >= got_addr && stub <= got_addr + got_size)
            {
                // Can actually just go by offset in got.. don't need to get
                // offset, because we know it's inside section
                uint64_t *resolved = getPointerToAddr(stub);
                if (splitKext || !resolved)
                {

                    off = stub - got_addr + got_off;
                    resolved = ((uint64_t *)(splitKext + off));
                }

                if (g_jdebug)
                    fprintf(stderr, "Stub at 0x%llx (offset 0x%x) is 0x%llx\n", stub, off, *resolved);

                if (resolved)
                    sym = getClosestSymbol(*resolved,       // unsigned long long addr,
                                           kernelSymTable); // struct symtabent *symtab);

                if (!sym)
                {
                    fprintf(stderr, "Unable to resolve kernel symbol at %llx (this is fine if it's a symbol from another kext)\n", *resolved);
                    sprintf(res, "unknown_0x%llx", resolved);
                }
                else
                {
                    if (g_jdebug)
                        fprintf(stderr, "Symbol at 0x%llx is %s (0x%llx)\n",
                                resolved, sym->sym, sym->ptr);

                    strcpy(res, sym->sym);
                }

                if (!companionFileFD)
                {
                    // time to open companionFileFD
                    sprintf(filename, "%s.ARM64.%s", buf, getUUID(mmapped));

                    companionFileFD = open(filename, O_RDWR | O_CREAT);

                    if (companionFileFD < 0)
                    {
                        fprintf(stderr, "Unable to open companion file %s.. Not symoblicating this kext\n");
                        return 0;
                    }
                    //		else fprintf(stderr,"Opened companion file %s\n", filename);

                    fchmod(companionFileFD, 0666);
                }
                sprintf(buf, "%llx:%s.stub\n", stubs_addr + pos, res);
                // if (jtoolOutFD > 0) write (jtoolOutFD, buf, strlen(buf));
                write(companionFileFD, buf, strlen(buf));
            }

            else
                fprintf(stderr, "Warning: Resolved stub in %s falls outside GOT (0x%llx not in 0x%llx-0x%llx)\n", Name, stub, got_addr, got_addr + got_size);

            sym = NULL;

        } //

        pos += 12;
    }

    char *segName = NULL;
    xnu3757_and_later = MachOGetSection("__DATA_CONST.__const");
    if (xnu3757_and_later)
    {
        segName = "__DATA_CONST.__const";

        jtoolOutFD = companionFileFD;
        int foundPolicy = doPolicyOps(splitKext, segName);
        jtoolOutFD = 0;
    }

    if (pos != stubs_size)
    {
        fprintf(stderr, "Warning: Disassembly left some unhandled instructions!\n");
    }

    close(companionFileFD);

    fprintf(stderr, "Symbolicated stubs to %s\n", filename);
    if (filename && (strstr(filename, "sandbox")))
    {
        if (xnu3757_and_later)
        {
            fprintf(stderr, "This is the sandbox.kext - Trying to get seatbelt-profiles\n");
            if (doSandboxOperationNames(splitKext, "__TEXT.__cstring"))
            {
                fprintf(stderr, "Can't get profiles with sandbox operation names\n");
            }
            doSandboxProfiles(splitKext, "__TEXT.__const");
        }
    }

    return 0;
}

int doKextract(char *mmapped, char *Name, int Size)
{
    uint32_t magic = MH_MAGIC;
    uint32_t magic64 = MH_MAGIC_64;

    uint32_t *magicAtAddress = (uint32_t *)mmapped;

    //printf("KEXTRACTING FROM %p\n", mmapped);
    if ((*magicAtAddress != MH_MAGIC) &&
        (*magicAtAddress != MH_MAGIC_64))
    {
        fprintf(stderr, "No magic at extraction address (0x%x)!\n", *magicAtAddress);
        return -5;
    }

    //	if (((int)mmapped) & 0xfff) return 0;
    if (g_jdebug)
        fprintf(stderr, "kextracting %s from %p\n", Name, mmapped);

    // Extract - create a file, and seek from here to the next Magic
    // YES, this will fail on the last kext. But hey - you can fix the
    // code easily. I just never need this for anything but AMFI, Sandbox, etc..

    char *nextMagic = mmapped + 0x1000;

    while (memcmp(nextMagic, magicAtAddress, sizeof(uint32_t)) != 0)
    {
        nextMagic += 0x10;

        //	printf("Next %p\n",nextMagic);
    }

    Size = nextMagic - mmapped;

    unsigned char *kextCopy = (unsigned char *)malloc(Size);

    memcpy(kextCopy, mmapped, Size);

    uint32_t __DATA__data_off = MachOGetSectionOffset(kextCopy, "__DATA.__data");

    segments = processFile(kextCopy, Size, getKernelCacheArch(), 0, 0, 0);

    uint32_t __DATA__data_size = MachOGetSectionSize(kextCopy, "__DATA.__data");

    uint32_t __DATA__CONST_const_off = MachOGetSectionOffset(kextCopy, "__DATA_CONST.__const");

    // Ok - we're here, so..
    int split = 0;
    char *d = getenv("JOKER_DIR");
    if (!d)
        d = "/tmp";

    char dumped[1024];
    snprintf(dumped, 1024, "%s/%s.kext", d, Name);

    int fd = open(dumped, O_RDWR | O_CREAT | O_TRUNC);
    printf("Writing kext out to %s\n", dumped);

    if (fd < 0)
    {
        printf("Unable to create file %s!\n", Name);
        return -2;
    }
    fchmod(fd, 0666);

    if (__DATA__CONST_const_off ||
        xnu3757_and_later)
    {

        split = 1;
        if (g_jdebug)
            fprintf(stderr, "This is a split kext. There's other parts, too...:\n");
        // iterate over the segments

        extern struct load_command *loadCommands[];

        int lc = 0;
        int writ = 0;
        for (lc = 0; loadCommands[lc]; lc++)
        {

            // Segments hold both segments/sections. We can tell difference by value of SEGMENT_COMMAND
            int bw = 0;
            struct segment_command_64 *sc = (struct segment_command_64 *)loadCommands[lc];
            if (sc->cmd == LC_SEGMENT_64)
            {
                if (g_jdebug)
                    fprintf(stderr, "Segment: %s at addr: 0x%llx-0x%llx, offset  0x%llx-0x%llx (Size: 0x%x)\n", sc->segname, sc->vmaddr, sc->vmaddr + sc->vmsize, sc->fileoff, sc->fileoff + sc->filesize, sc->filesize);

                int off = lseek(fd, 0, SEEK_CUR);

                char *from = mmapped + sc->fileoff;

                if (sc->vmaddr >= prelink_data_data_addr &&
                    sc->vmaddr <= prelink_data_data_addr + prelink_data_data_size)
                {
                    fprintf(stderr, "Workaround for Apple's offset bug in the kernelcache!\n");
                    from = getKernelCacheStart() + prelink_data_data_offset + (sc->vmaddr - prelink_data_data_addr);
                }

                bw = write(fd, from, sc->filesize);
                if (bw < 0)
                {
                    perror("write");
                    // this is a BUG in the sc->fileoff!
                    // have to go by vmaddr
                    fprintf(stderr, "Unable to write out segment %s of %x bytes (0x%llx) from offset 0x%x-0x%x! Failing!!!\n", sc->segname, sc->filesize, sc->vmaddr, sc->fileoff, sc->fileoff + sc->filesize);
                    exit(1);
                }
                // bw= write (fd, (getKernelCacheStart() + sc->fileoff), sc->filesize);

                ///	fprintf(stderr," BW is 0x%x\n", bw); }

                else
                {
                    if (g_jdebug)
                        fprintf(stderr, "Written out segment %s (0x%llx) from offset 0x%x\n", sc->segname, sc->vmaddr, sc->fileoff);
                    bw = 0;
                }

                if (g_jdebug)
                {
                    //  fprintf(stderr,"..Written %x bytes (%llx) to offset 0x%x (0x%x)\n", bw,writ, *((((unsigned char *)mmapped) + sc->fileoff)), off);
                }
                writ += bw;

                int patch = sc->fileoff - off;

                if (g_jdebug)
                    fprintf(stderr, "Patching load command %p in kextCopy %p from 0x%x to 0x%x\n", sc, kextCopy, sc->fileoff, off);

                sc->fileoff = off;

                // Should also do for segments:
                int sect = 0;
                struct section_64 *sec64 = (struct section_64 *)(sc + 1);

                //int extra;
                for (sect = 0; sect < sc->nsects; sect++)
                {

                    // extra = sec64->addr & 0xfff;

                    if (sec64->offset)
                    {
                        if (g_jdebug)
                        {
                            fprintf(stderr, "Patching section %s from 0x%llx-0x%llx to 0x%llx.. (%llx bytes)\n",
                                    sec64->sectname, sec64->offset, sec64->offset + sec64->size,
                                    (sec64->offset - patch), patch);
                        }
                    }

                    if (sec64->offset)
                    {
                        /*	char *extraPad = calloc (extra, 1);
				write (fd, extraPad,extra);
				free(extraPad);
			//	writ+= extra;

				*/
                        sec64->offset = (sec64->offset - patch);
                        off += sec64->size;
                    }
                    sec64++;
                }

                off = lseek(fd, 0, SEEK_CUR);
                // Pad to a page boundary!
                if (off)
                {
                    int pad = 0x1000 - (off % 0x1000);
                    char *padding = calloc(pad, 1);
                    if (g_jdebug)
                        fprintf(stderr, "Padding by 0x%x bytes\n", pad);
                    write(fd, padding, pad);
                    writ += pad;
                    free(padding);
                }

            } // lc_segment

        } // end for

        // Now patch header:

        if (g_jdebug)
            fprintf(stderr, "Applying patched header...\n");
        int rc = lseek(fd, 0, 0);
        rc = write(fd, kextCopy, 4096);

        if (g_jdebug)
            fprintf(stderr, " written %d bytes\n", writ);
    }
    else
    {
        // Simple case - we have all the kext.
        write(fd, mmapped, nextMagic - mmapped);
    }

    close(fd);
    // Want to get the Kext symbol Stubs now!
    symbolicateKextStubs(mmapped, nextMagic - mmapped, Name, split);

    //printf ("Extracted %s\n", Name);
    return (0);
}

void doKexts(char *mmapped, char *kextractThis, int method)
{
    int kexts = 0;

    // To do the kexts, we load the dictionary of PRELINK_INFO
    char *kextPrelinkInfo = (char *)malloc(1000000);
    char *kextNamePtr;
    char *kextLoadAddr;
    char kextName[2560];
    char loadAddr[24];
    char *temp = kextPrelinkInfo;
    char *loadAddrPtr;
    char *prelinkAddr;

    extern char *g_SegName;

    g_SegName = "__PRELINK_INFO";

    struct section *segPI = MachOGetSection((unsigned char *)"__PRELINK_INFO.__info");
    struct section_64 *segPI64 = (struct section_64 *)segPI;
    struct section *segPT = MachOGetSection((unsigned char *)"__PRELINK_TEXT.__text");
    struct section_64 *segPT64 = (struct section_64 *)segPT;

    if (!segPT64 || !segPI64)
        return;
    if (kextractThis)
    {
        if (g_jdebug)
            fprintf(stderr, "Attempting to kextract %s\n", kextractThis);
    };
    uint64_t offsetCorrection = (is64 ? segPT64->addr - segPT64->offset : segPT->addr - segPT->offset);

    int offset = (is64 ? segPI64->offset : segPI->offset);

    // PRELINK_TEXT will look something link this:
    // Mem: 0x8044f000-0x80eee000      File: 0x00406000-0x00ea5000

    kextPrelinkInfo = (char *)(mmapped + offset);
    temp = kextPrelinkInfo;
    if (!temp)
    {
        printf("Unable to find __PRELINK_INFO\n");
        return;
    }

    kextNamePtr = strstr(temp, "CFBundleName</key>");

    if (method == 1)
        // This is EXTREMELY quick and dirty, but I can't find a way to load a CFDictionary
        // directly from XML data (and be cross platform), so it will do for now..
        //
        // ... and it's getting dirtier still but at least I fixed the ID=...
        // Definitely clean this up sometime... especially now that INFO is used..
        //
        while (kextNamePtr)
        {
            temp = strstr(kextNamePtr, "</string>");

            prelinkAddr = strstr(kextNamePtr, "_PrelinkExecutableLoadAddr");
            if (!prelinkAddr)
            {

                //	prelinkAddr= strstr(kextNamePtr, "_PrelinkExecutable");

                if (!prelinkAddr)
                {

                    fprintf(stderr, "Can't determine kext load addr.. This might be a really old kernelcache. Max - trying method #2 for you..\n");
                    break;
                }
            }

            loadAddrPtr = strstr(prelinkAddr, "0x");
            // overflow, etc..
            memset(kextName, '\0', 2560);
            // fix for ID=..
            char *idFix = NULL;
            //	idFix = strstr(kextNamePtr, ">");
            idFix = strnstr(kextNamePtr, "ID=\"", temp - kextNamePtr);

            if (!idFix)
                idFix = kextNamePtr + 26;
            else
                idFix = strstr(idFix + 5, "\">") + 2;

            strncpy(kextName, idFix, temp - idFix);

            //	temp = strstr(loadAddrPtr, "</integer>");

            char *endOfLoadAddr = strchr(loadAddrPtr, '<');

            memset(loadAddr, '\0', 24);
            strncpy(loadAddr, loadAddrPtr, 11 + (is64 ? 7 : -1));

            if (!kextractThis)
                printf("%s: %s ", loadAddr, kextName);

            temp += 10;

            kextNamePtr = strstr(temp, "CFBundleIdentifier");

            if (kextNamePtr)
            {
                temp = strstr(kextNamePtr, "</string>");
                memset(kextName, '\0', 256);

                idFix = strnstr(kextNamePtr, "ID=\"", temp - kextNamePtr);

                if (!idFix)
                    idFix = kextNamePtr + 32;
                else
                    idFix = strstr(idFix + 5, "\">") + 2;

                strncpy(kextName, idFix, temp - idFix);

                if (!kextractThis)
                    printf("(%s)\n", kextName);
                else
                {
                    //printf("FOUND %s\n", kextName);
                    if ((strcmp(kextractThis, "all") == 0) || strstr(kextractThis, kextName))
                    {
                        uint64_t addr;
                        int rc = sscanf(loadAddr, "%llx", &addr);
                        if (!rc)
                        {
                            fprintf(stderr, "Unable to parse load address %x!\n", loadAddr);
                            exit(3);
                        }
                        printf("Found %s at load address: %llx, offset: %x\n", kextName, addr, addr - offsetCorrection);
                        (doKextract(mmapped + (addr - offsetCorrection), kextName, 0));

                        // zzzzz
                    }
                }
            }
            kextNamePtr = strstr(temp, "CFBundleName</key>");

            kexts++;
        }

    if (g_jdebug)
        fprintf(stderr, "--METHOD: %d\n", method);

    if (method == 1 && kexts > 50)
    {
        if (!kextractThis)
            fprintf(stderr, "Got %d kexts %s\n", kexts, (kexts > 200 ? "(yowch!)" : ""));
        return;
    }
    else
    {
        fprintf(stderr, "Number of kexts way too small.. Trying method #2\n", kexts);
    }

    // Method #2 - applicable for kernel dumps

    fprintf(stderr, "Unable to get kexts from __PRELINK_INFO.. going straight for __PRELINK_TEXT\n");

    if (!segPT)
    {
        printf("This is weird. Can't get offset of __PRELINK_TEXT. Giving up..\n");
        return;
    }

    offset = (is64 ? segPT64->offset : segPT->offset);

    int size = (is64 ? segPT64->size : segPT->size);

    uint32_t machOSig = (is64 ? 0xfeedfacf : 0xfeedface);

    int prev = 0;
    int k = 1;
    int i = 0;
    for (i = 0;
         i < size;
         i += 0x1000)
    {
        if (memcmp(&mmapped[offset + i], &machOSig, sizeof(uint32_t)) == 0)
        {
            if (!prev)
            {
                prev = offset + i;
            }
            else
            {

                int kextSize = (offset + i - prev);
                struct mach_header_64 *mh = (struct mach_header_64 *)((&mmapped[offset + i]));

                if (mh->filetype != 0xb) // change to kext const
                {
                    fprintf(stderr, "Got Mach-O magic but not a kext. Continuing\n");
                    continue;
                }

                if (g_jdebug)
                    fprintf(stderr, "IN KEXT %d (%d/%d), kextSize: %d\n", k,
                            i, size, kextSize);

                if (kextSize + i > size)
                {
                    fprintf(stderr, "kext size reported is greater than remaining dump bytes.. skipping\n");
                    i++;
                    continue;
                }

                char *kextID = identifyKextNew(&mmapped[prev], kextSize, mmapped);

                // fallback to older method
                if (!kextID)
                    kextID = identifyKext(&mmapped[prev], kextSize);

                if (!kextID)
                    kextID = "unrecognized.or.unhandledyet.Please.Report.Me";

                // process
                if (kextractThis)
                {
                    if ((strcmp(kextractThis, "all") == 0) || strstr(kextID, kextractThis))
                    {

                        char *kextfile = strdup(kextID);
                        char *space = strchr(kextfile, '(');
                        if (space)
                            space[0] = '\0';

                        char dumped[1024];

                        doKextract(mmapped + prev, kextfile, 0);
                        /*
				snprintf(dumped, 1024, "%s/%d.%s.kext",d, k, kextfile);
				printf("Writing kext out to %s\n",dumped);
				int fd = open (dumped, O_WRONLY | O_TRUNC | O_CREAT);
				if (fd < -1) { perror (dumped); }
				else
				{
				  fchmod(fd, 0600);
				  write (fd, &mmapped[prev], (offset +i - prev));
			   	  close(fd);

				}
*/
                        free(kextfile);
                    }
                }
                else
                { // just print
                    printf("%d: %s at 0x%x (%x bytes)\n", k, kextID, prev, (offset + i - prev));
                }

                // if (kextractThis && strstr (kextID, kextractThis)) { exit (doKextract (mmapped + prev, kextractThis)); }

                prev = offset + i;
                k++;
            }
        }

    } // end for
}

struct sysctl_oid
{
    uint32_t ptr_oid_parent;
    uint32_t ptr_oid_link;
    int oid_number;
    int oid_kind;
    uint32_t oid_arg1;
    int oid_arg2;
    uint32_t ptr_oid_name;
    uint32_t ptr_oid_handler;
    uint32_t ptr_oid_fmt;
    uint32_t ptr_oid_descr; /* offsetof() field / long description */
    int oid_version;
    int oid_refcnt;
};

struct sysctl_oid_64
{
    uint64_t ptr_oid_parent;
    uint64_t ptr_oid_link;
    int oid_number;
    int oid_kind;
    uint64_t oid_arg1;
    int oid_arg2;
    uint64_t ptr_oid_name;
    uint64_t ptr_oid_handler;
    uint64_t ptr_oid_fmt;
    uint64_t ptr_oid_descr; /* offsetof() field / long description */
    int oid_version;
    int oid_refcnt;
};

typedef struct sysctlNamespace
{
    char *name;
    uint64_t addr;
    int resolved;

} sysctlNamespace_t;

sysctlNamespace_t sysctlNamespaces[256];

int sysctlNamespaceCount = 0;

void addSysctlNamespace(uint64_t addr, char *name)
{
    // fprintf(stdout," Adding: 0x%llx - %s\n", addr, name);

    sysctlNamespaces[sysctlNamespaceCount].name = name;
    sysctlNamespaces[sysctlNamespaceCount].addr = addr;
    sysctlNamespaces[sysctlNamespaceCount].resolved = (strstr(name, "0x")) ? 0 : 1;
    sysctlNamespaceCount++;
}

char *getSysctlNamespaceName(uint64_t Addr)
{

    int ns = 0;
    for (ns = 0; ns < sysctlNamespaceCount; ns++)
    {
        if (sysctlNamespaces[ns].addr == Addr)
            return sysctlNamespaces[ns].name;
    }

    return (NULL);
}

char *sysctlName(char *mmapped, uint64_t sysctlPtr)
{

    char *name = malloc(1024);

    name[0] = '\0';
    uint32_t sysCtlOffsetInFile = MachOGetFileOffsetOfAddr(sysctlPtr);
    if (sysCtlOffsetInFile == -1)
    {
        strcat(name, "?");
        return (name);
    }

    struct sysctl_oid *sysctl = (mmapped + sysCtlOffsetInFile);
    struct sysctl_oid_64 *sysctl64 = (struct sysctl_oid_64 *)sysctl;

    char *parent = MachOLookupSymbolAtAddress((is64 ? sysctl64->ptr_oid_parent : sysctl->ptr_oid_parent),
                                              (unsigned char *)mmapped);

    struct section *sec = MachOGetSection((unsigned char *)"__DATA.__sysctl_set");
    struct section_64 *sec64 = (struct section_64 *)sec;

    if (!sec64)
    {
        fprintf(stderr, "Unable to get section!\n");
    }
    // printf("PARENT: %llx, sec: %llx-%llx\n", sysctl64->ptr_oid_parent, sec64->addr, sec64->addr+sec64->size);;
    char *parentName = getSysctlNamespaceName(is64 ? sysctl64->ptr_oid_parent : sysctl->ptr_oid_parent);

    if (parentName)
    {
        strcpy(name, parentName);
        if (parentName[0])
            strcat(name, ".");
    }

    if (!name)
    {
        char parentAddr[20];
        sprintf(parentAddr, "0x%llx", (is64 ? sysctl64->ptr_oid_parent : sysctl->ptr_oid_parent));
        strcpy(name, parentAddr);
        strcat(name, ".");
    }

    uint32_t sysctlNameOffsetInFile = MachOGetFileOffsetOfAddr(is64 ? sysctl64->ptr_oid_name : sysctl->ptr_oid_name);

    if (sysctlNameOffsetInFile == -1)
    {
        strcat(name, "?");
        return (name);
    }

    strcat(name, mmapped + sysctlNameOffsetInFile);

    return (name);

} //sysctlName

void doSysctls(char *mmapped, int is64)
{
    // assume section 32 for now..
    struct section *sec = MachOGetSection((unsigned char *)"__DATA.__sysctl_set");
    struct section_64 *sec64 = (struct section_64 *)sec;
    if (sec)
    {
        int numsysctls = (is64 ? sec64->size : sec->size) / (is64 ? sizeof(uint64_t) : sizeof(uint32_t));

        int s = 0;

        uint64_t offset = (is64 ? sec64->offset : sec->offset);
        uint64_t addr = (is64 ? sec64->addr : sec->addr);
        uint64_t size = (is64 ? sec64->size : sec->size);

        printf("Dumping sysctl_set from 0x%llx (offset in file: 0x%llx), %x sysctls follow:\n", addr, offset, numsysctls);

        int i = 0;
        for (i = 0; i < 2; i++)
        {

            // First pass: get namespaces - works better in reverse!
            for (s = numsysctls - 1; s >= 0; s--)
            {
                uint64_t sysctlPtr;

                if (is64)
                {
                    sysctlPtr = *((uint64_t *)(mmapped + offset + s * sizeof(uint64_t)));
                }
                else
                    sysctlPtr = *((uint32_t *)(mmapped + offset + s * sizeof(uint32_t)));
                uint64_t sysctlOffsetInFile = MachOGetFileOffsetOfAddr(sysctlPtr);

                // sanity check, anyone?

                if (!is64 && (sysctlOffsetInFile > sec->offset + sec->size))
                {
                    printf("(%llx outside __sysctl_set)\n", sysctlPtr);
                    continue;
                };
                if (is64 && (sysctlOffsetInFile > offset + size))
                {
                    printf("(%llx is outside __sysctl_set)\n", sysctlPtr);
                    continue;
                };

                struct sysctl_oid *sysctl = (mmapped + sysctlOffsetInFile);
                struct sysctl_oid_64 *sysctl64 = (struct sysctl_oid_64 *)sysctl;
                uint32_t sysctlDescInFile = MachOGetFileOffsetOfAddr(is64 ? sysctl64->ptr_oid_descr : sysctl->ptr_oid_descr);

                uint32_t sysctlFormatInFile = MachOGetFileOffsetOfAddr(is64 ? sysctl64->ptr_oid_fmt : sysctl->ptr_oid_fmt);
                char *sysctlFormat = "?";
                if (sysctlFormatInFile != -1)
                {
                    sysctlFormat = mmapped + sysctlFormatInFile;
                }

                uint64_t handler = is64 ? sysctl64->ptr_oid_handler : sysctl->ptr_oid_handler;

                if (!handler)
                {
                    char *nsname = sysctlName(mmapped, sysctlPtr);
                    if ((i == 0))
                    {
                        if (strstr(nsname, "kperf"))
                        {
                            addSysctlNamespace(is64 ? sysctl64->ptr_oid_parent : sysctl->ptr_oid_parent, "");
                        }
                    }
                    else
                        addSysctlNamespace(is64 ? sysctl64->oid_arg1 : sysctl->oid_arg1, nsname);
                }
            }

        } // 2 passes

        // Second pass:

        for (s = 0; s < numsysctls; s++)
        {

            uint64_t sysctlPtr;

            if (is64)
            {
                sysctlPtr = *((uint64_t *)(mmapped + offset + s * sizeof(uint64_t)));
            }
            else
                sysctlPtr = *((uint32_t *)(mmapped + offset + s * sizeof(uint32_t)));

            uint64_t sysctlOffsetInFile = MachOGetFileOffsetOfAddr(sysctlPtr);
            //printf ("0x%llx: ", sysctlPtr , sysctlOffsetInFile);

            // sanity check, anyone?

            if (!is64 && (sysctlOffsetInFile > sec->offset + sec->size))
            {
                printf("(outside __sysctl_set)\n");
                continue;
            };
            if (is64 && (sysctlOffsetInFile > offset + size))
            {
                printf("(outside __sysctl_set)\n");
                continue;
            };

            struct sysctl_oid *sysctl = (mmapped + sysctlOffsetInFile);
            struct sysctl_oid_64 *sysctl64 = (struct sysctl_oid_64 *)sysctl;
            uint32_t sysctlDescInFile = MachOGetFileOffsetOfAddr(is64 ? sysctl64->ptr_oid_descr : sysctl->ptr_oid_descr);

            uint32_t sysctlFormatInFile = MachOGetFileOffsetOfAddr(is64 ? sysctl64->ptr_oid_fmt : sysctl->ptr_oid_fmt);
            char *sysctlFormat = "?";
            if (sysctlFormatInFile != -1)
            {
                sysctlFormat = mmapped + sysctlFormatInFile;
            }

            uint64_t handler = is64 ? sysctl64->ptr_oid_handler : sysctl->ptr_oid_handler;

            if (!handler)
                continue; // covered these in first pass...
            printf("0x%llx: ", sysctlPtr, sysctlOffsetInFile);

            char *name = sysctlName(mmapped, sysctlPtr);
            uint64_t arg1 = is64 ? sysctl64->oid_arg1 : sysctl->oid_arg1;
            printf((is64 ? "%s\tDescription: %s\n\t\tHandler: 0x%llx\n\t\tFormat: %s\n\t\tParent: 0x%llx\n\t\tArg1: %llx\n\t\tArg2: 0x%llx\n"
                         : "%s\tDescription: %s\n\t\tHandler: 0x%x\n\t\tFormat: %s\n\t\tParent: 0x%x\n\t\tArg1: %x\n\t\tArg2: 0x%x\n"),

                   name,
                   mmapped + sysctlDescInFile,
                   handler,
                   sysctlFormat,
                   is64 ? sysctl64->ptr_oid_parent : sysctl->ptr_oid_parent,
                   arg1,
                   is64 ? sysctl64->oid_arg2 : sysctl->oid_arg2);

            if ((arg1 > 0x80000000) && wantJToolOut)
            {
                char output[1024];
                addSymbolToCache(name, arg1, NULL);

                //		 sprintf (output, "0x%llx:%s\n", arg1, name);
                //	 write (jtoolOutFD, output, strlen(output));
            }
        }
    }

} // doSysctls

void doMachTraps(char *mmapped, int xnu32xx)
{
    char *zeros = calloc(24, 1);
    struct section_64 *segDC = MachOGetSection((unsigned char *)"__DATA.__const");
    if (!segDC)
        segDC = MachOGetSection((unsigned char *)"__CONST.__constdata");
    if (!segDC)
    {
        segDC = MachOGetSection((unsigned char *)"__DATA_CONST.__const");
    }

    if (!segDC)
    {
        fprintf(stderr, "No __DATA.__const or __CONST??!\n");
        return;
    }
    struct section *segDC32 = (struct section *)segDC;

    int offset = (is64 ? segDC->offset : segDC32->offset);
    int adv = (is64 ? 8 : 4);
    int i = 0;
    char *mach = NULL;
    char *pos = mmapped + offset;
    uint64_t segAddr = (is64 ? segDC->addr : segDC32->addr);
    uint32_t segOffset = (is64 ? segDC->offset : segDC32->offset);
    int segSize = (is64 ? segDC->size : segDC32->size);
    int skip = (is64 ? 3 : 5);

    for (i = 0; i < segSize; i += adv)

        // Ugly, I know, but works in both 32 and 64-bit cases

        if ((((memcmp(&pos[i], zeros, skip * adv) == 0) &&
              (memcmp(&pos[i + (skip + 1) * adv], zeros, skip * adv) == 0) &&
              (memcmp(&pos[i + 2 * (skip + 1) * adv], zeros, skip * adv) == 0) &&
              (memcmp(&pos[i + 3 * (skip + 1) * adv], zeros, skip * adv) == 0) &&
              (memcmp(&pos[i + 4 * (skip + 1) * adv], zeros, skip * adv) == 0) &&
              ((*((uint64_t *)&pos[i - adv])) && *((int64_t *)&pos[i + skip * adv])))))
        {
            printf("mach_trap_table offset in file/memory (for patching purposes): 0x%x/%llx\n", segOffset + i, segAddr + i);
            mach = &pos[i] - adv;
            dumpMachTraps(mach, is64);
            break;
        }

} // doMachTraps

void doMIG(char *mmapped, int xnu32xx)
{
    struct section_64 *segDC = MachOGetSection((unsigned char *)"__DATA.__const");
    if (!segDC)
        segDC = MachOGetSection((unsigned char *)"__CONST.__constdata");
    if (!segDC)
    {
        segDC = MachOGetSection((unsigned char *)"__DATA_CONST.__const");
    }
    if (!segDC)
    {
        fprintf(stderr, "No __DATA.__const?!\n");
        return;
    }
    struct section *segDC32 = (struct section *)segDC;

    int offset = (is64 ? segDC->offset : segDC32->offset);
    int adv = (is64 ? 8 : 4);
    int i = 0;
    char *pos = mmapped + offset;
    uint32_t subsysMachVM = 0;
    uint32_t subsysTask = 0;

    uint64_t segAddr = (is64 ? segDC->addr : segDC32->addr);
    int segSize = (is64 ? segDC->size : segDC32->size);

    for (i = 0; i < segSize; i += adv)
    {
        if (memcmp(&pos[i], &mach_vm_subsys, 8) == 0)
        {
            printf("mach_vm_subsystem is  @0x%llx!\n", segAddr + i - adv);
            subsysMachVM = offset + i;
            dumpMIGSubsystem((mig_subsys *)(pos + i), &mach_vm_subsys, is64);
        }

        if (memcmp(&pos[i], &thread_act_subsys, 8) == 0)
        {
            printf("thread_act_subsystem is  @0x%llx!\n", segAddr + i - adv);
            dumpMIGSubsystem((mig_subsys *)(pos + i), &thread_act_subsys, is64);
        }
        if (memcmp(&pos[i], &mach_port_subsys, 8) == 0)
        {
            printf("mach_port_subsystem is  @0x%llx!\n", segAddr + i - adv);
            dumpMIGSubsystem((mig_subsys *)(pos + i), &mach_port_subsys, is64);
        }

        if (memcmp(&pos[i], (xnu32xx ? &is_iokit_subsys_9 : &is_iokit_subsys), 4) == 0)
        {
            printf("is_iokit_subsystem is  @0x%llx!\n", segAddr + i - adv);
            dumpMIGSubsystem((mig_subsys *)(pos + i), &is_iokit_subsys, is64);
        }

        if (memcmp(&pos[i], (&processor_subsys), 8) == 0)
        {
            printf("processor_subsystem is  @0x%llx!\n", segAddr + i - adv);
            dumpMIGSubsystem((mig_subsys *)(pos + i), &processor_subsys, is64);
        }
        if (memcmp(&pos[i], (&processor_set_subsys), 8) == 0)
        {
            printf("processor_set_subsystem is  @0x%llx!\n", segAddr + i - adv);
            dumpMIGSubsystem((mig_subsys *)(pos + i), &processor_set_subsys, is64);
        }
        if (memcmp(&pos[i], (&host_security_subsys), 8) == 0)
        {
            printf("host_security_subsystem is  @0x%llx!\n", segAddr + i - adv);
            dumpMIGSubsystem((mig_subsys *)(pos + i), &host_security_subsys, is64);
        }

        if (memcmp(&pos[i], &host_priv_subsys, 8) == 0)
        {
            printf("host_priv_subsystem is  @0x%llx!\n", segAddr + i - adv);

            dumpMIGSubsystem((mig_subsys *)(pos + i), &host_priv_subsys, is64);
        }

        if (memcmp(&pos[i], (&mach_host_subsys_9), 4) == 0)
        {
            printf("mach_host_subsystem is  @0x%llx!\n", segAddr + i - adv);
            dumpMIGSubsystem((mig_subsys *)(pos + i), &mach_host_subsys_9, is64);
        }

        if (memcmp(&pos[i], &task_subsys, 4) == 0)
        {
            printf("task_subsystem is  @0x%llx!\n", segAddr + i - adv);
            subsysTask = offset + i;
            dumpMIGSubsystem((mig_subsys *)(pos + i), &task_subsys, is64);
        }
    }

} //doMig

uint64_t look_for_inst(char *Func, uint32_t Inst, char *Where, int Size, uint64_t addr, int jtoolOutFD)
{

    // fprintf(stderr,"Looking for %s ...\n", Func);

    char *found = memmem(Where, Size, &Inst, 4);
    if (found)
    {
        fprintf(stderr, "Found %s at offset 0x%x, Addr: 0x%llx\n",
                Func,
                found - (Where),
                addr + (found - Where));

        addSymbolToCache(Func, addr + (found - Where), NULL);

        //char output[1024];
        //	sprintf(output, "%llx:_%s\n", addr + (found - Where), Func);
        //write (jtoolOutFD, output, strlen(output));
    }

    return (addr + (found - Where));
} // look_for_inst

struct compHeader
{
    char sig[8];      // "complzss"
    uint32_t unknown; // Likely CRC32. But who cares, anyway?
    uint32_t uncompressedSize;
    uint32_t compressedSize;
    uint32_t unknown1; // 1
};

char *tryLZSS(char *compressed, int *filesize)
{
    struct compHeader *compHeader = strstr(compressed, "complzss");

    if (!compHeader)
        return (NULL);

    fprintf(stderr, "Feeding me a compressed kernelcache, eh? That's fine, now. I can decompress! ");

    if (!g_dec)
        fprintf(stderr, "(Type -dec _file_ if you want to save to file)!");

    fprintf(stderr, "\nCompressed Size: %d, Uncompressed: %d. Unknown: 0x%x, Unknown 1: 0x%x\n",
            ntohl(compHeader->compressedSize),
            ntohl(compHeader->uncompressedSize),
            ntohl(compHeader->unknown),
            ntohl(compHeader->unknown1));

    int sig[2] = {0xfeedfacf, 0x0100000c};

    // But check for KPP:
    char *found = NULL;
    if ((found = memmem(mmapped + 0x2000, *filesize, "__IMAGEEND", 8)))
    {
        // the 0xfeedfacf before that is kpp..
        char *kpp = memmem(found - 0x1000, 0x1000, sig, 4);
        if (kpp)
        {
            fprintf(stderr, "btw, KPP is at %lld (0x%x)", kpp - mmapped, kpp - mmapped);
            int out = open("/tmp/kpp", O_TRUNC | O_CREAT | O_WRONLY);
            if (out < 0)
            {
                fprintf(stderr, "But I can't save it for you\n");
                exit(3);
            }

            fchmod(out, 0600);
            write(out, kpp, *filesize - (kpp - mmapped));
            close(out);
            fprintf(stderr, "..And I saved it for you in /tmp/kpp\n");
        }
    }

    // For lzss I'm using code verbatim from BootX, which, like Apple, is ripped from
    // Haruhiko Okumura (CompuServe 74050,1022, if anyone can find him to thank him from me!)
    // Code is: from BootX-81//bootx.tproj/sl.subproj/lzss.c
    //
    // The code is in the public domain, Stefan, I'm not stealing anything.
    // Unlike people who never credit OpenSSL in their Apps ;-)
    //

    // I trust AAPL to report sizes and not give me a heap overflow now ;-)

    char *decomp = malloc(ntohl(compHeader->uncompressedSize));

    // find kernel 0xfeedfa... If I ever support 32-bit, I'll need faCE or faCF..
    int MachOSig = 0xfeedfacf;
    char *feed = memmem(mmapped + 64, 1024, &MachOSig, 3);

    if (!feed)
    {
        fprintf(stderr, "Can't find kernel here.. Sorry. LZSS this yourself\n");
        exit(5);
    }
    else
    {
        fprintf(stderr, "Got kernel at %d\n", feed - mmapped);
    }

    feed--;
    int rc = decompress_lzss(decomp,
                             feed,
                             ntohl(compHeader->compressedSize));
    if (rc != ntohl(compHeader->uncompressedSize))
    {
        fprintf(stderr, "Expected %d bytes ... Got %d bytes. Aborting\n",
                ntohl(compHeader->uncompressedSize), rc);
    }

    *filesize = rc;

    if (g_dec)
    {
        int fd = open("/tmp/kernel", O_WRONLY | O_CREAT | O_TRUNC);
        if (fd < 0)
        {
            fprintf(stderr, "Can't write decompressed kernel to /tmp/kernel...\n");
        }
        else
        {
            fchmod(fd, 0600);
            write(fd, decomp, ntohl(compHeader->uncompressedSize));
            close(fd);
        }
    }
    return (decomp);

} // compLZSS

int main(int argc, char **argv)
{

    int xnu24xx = 0;
    int xnu27xx = 0;
    int xnu32xx = 0;
    int xnu37xx = 0;
    int iOS = 0;

    g_jdebug = (getenv("JDEBUG") != NULL);

    int fd;
    int rc;
    struct stat stbuf;
    int filesize;
    filename = argv[1];
    struct mach_header *mh;
    int i, j;
    int magic;
    char *sysent = NULL;
    uint64_t sysentAddr;
    char *mach = NULL;
    char *xnuSig = NULL;
    int showUNIX = 0, showMach = 0;
    int suppressEnosys = 1;
    int suppressOld = 1;

    int showVersion = 0;
    int showKexts = 0;
    int showSysctls = 0;
    char *kextName = NULL;
    int kextract = 0;

    FILE *jtoolOutFile = NULL;

    if (!filename)
    {
        fprintf(stderr, "Usage: joker [-j] [-MmaSsKk] _filename_\n", argv[0]);
        fprintf(stderr, " _filename_ should be a decrypted iOS kernelcache, or kernel dump. Tested on ARMv7/s 3.x-9.3, and ARM64 through 10.0.1GM\n\n");
        fprintf(stderr, " -m: dump Mach Traps and MIG tables (NEW)\n");
        fprintf(stderr, " -a: dump everything\n");
        fprintf(stderr, " -k: dump kexts\n");
        fprintf(stderr, " -K: kextract [kext_bundle_id_or_name_shown_in_-k|all] to JOKER_DIR or /tmp\n");
        fprintf(stderr, " -S: dump sysctls\n");
        fprintf(stderr, " -s: dump UNIX syscalls\n");
        fprintf(stderr, " -j: Jtool compatible output (to companion file)\n");

        fprintf(stderr, "\n-dec: Decompress kernelcache to /tmp/kernel (complzss only at this stage)\n");

        fprintf(stderr, "\nKernels not included. Get your own dump or decrypted kernel from iPhoneWiki, or Apple itself (as of iOS 10b1! Thanks, guys!)\n");
        fprintf(stderr, "\n3.0 with MACF Policies, stub symbolication, SPLIT KEXTS, Sandbox Profiles (beta, collections only at this point) , kpp and (coming soon) IOUserClients!\nCompiled on " __DATE__ "\n");

#ifdef HAVE_LZSS
        fprintf(stderr, "\nContains code from Haruhiko Okumura (CompuServe 74050,1022) from BootX-81//bootx.tproj/sl.subproj/lzss.c\n");
#endif
        exit(0);
    }

    if (filename[0] == '-')
    {
        showVersion = (filename[1] == 'v' ? 1 : 0);
        filename = argv[2];
    };
    int arg = 0;
    for (arg = 1; arg < argc - 1; arg++)
    {
        if (strcmp(argv[arg], "-k") == 0)
        {
            showKexts = 1;
            showUNIX = 0;
            showMach = 0;
        };
        if (strcmp(argv[arg], "-K") == 0)
        {
            kextract = 1;
            kextName = argv[arg + 1];
            filename = argv[argc - 1];
            showUNIX = 0;
            showMach = 0;
        };
        if (strcmp(argv[arg], "-S") == 0)
        {
            showSysctls = 1;
            filename = argv[2];
        };
        if (strcmp(argv[arg], "-a") == 0)
        {
            showSysctls = 1;
            showKexts = 1;
            filename = argv[2];
            showUNIX = showMach = 1;
        };
        if (strcmp(argv[arg], "-m") == 0)
        {
            showMach = 1;
        };
        if (strcmp(argv[arg], "-s") == 0)
        {
            showUNIX = 1;
        };
        if (strcmp(argv[arg], "-dec") == 0)
        {
            g_dec = 1;
        }
        if (strcmp(argv[arg], "-j") == 0)
        {
            wantJToolOut = 1;
        }
    }
    filename = argv[argc - 1];

    rc = stat(filename, &stbuf);

    if (rc == -1)
    {
        perror(filename);
        exit(1);
    }

    filesize = stbuf.st_size;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        exit(2);
    }

    mmapped = mmap(NULL,
                   filesize,              // size_t len,
                   PROT_READ,             // int prot,
                   MAP_SHARED | MAP_FILE, // int flags,
                   fd,                    // int fd,
                   0);                    // off_t offset);

    if (!mmapped)
    {
        perror("mmap");
        exit(3);
    }

    int xnu = 0;
    // Examine first

retry:

    mh = (struct mach_header *)(mmapped);
    if (mh->cputype == 12 || mh->cputype == 16777228) /* ARM */
    {
        iOS = 1;
    }
    else
    {
        iOS = 0;
    }

    switch (mh->magic)
    {
    case 0x496d6733: // IMG3
        fprintf(stderr, "Not handling IMG3. 32-bit is passe', man\n");
        exit(0);

    case 0xFEEDFACE:
        /* Good, this is a Mach-O */
        // This is an ARM binary. Good.
        setKernelCacheArch(CPU_TYPE_ARM);
        setKernelCacheStart(mmapped);
        segments = processFile((unsigned char *)mmapped, filesize, CPU_TYPE_ARM, 0, 0, 0);

        break;

    case 0xFEEDFACF:

        setKernelCacheArch(CPU_TYPE_ARM64);
        setKernelCacheStart(mmapped);
        segments = processFile((unsigned char *)mmapped, filesize, CPU_TYPE_ARM64, 0, 0, 0);
        is64++;
        break;
    case 0xbebafeca:
        fprintf(stderr, "This is an Intel FAT binary, but I can't handle these yet\n");
        exit(5);
    default:
    {
        // Could be we were fed a kernelcache
        int origSize = filesize;
        char *mem = tryLZSS(mmapped, &filesize);

        if (!mem)
        {
            fprintf(stderr, "I have no idea how to handle a file with a magic of 0%x\n", magic);
            exit(6);
        }

        munmap(mmapped, origSize);
        mmapped = mem;
        goto retry;
    }
    }

    // Got segments - get PLK_DATA_

    prelink_data_data_addr = MachOGetSectionAddr(mmapped, "__PRELINK_DATA.__data");
    prelink_data_data_offset = MachOGetSectionOffset(mmapped, "__PRELINK_DATA.__data");
    prelink_data_data_size = MachOGetSectionSize(mmapped, "__PRELINK_DATA.__data");

    struct source_version_command *svc = (struct source_version_command *)findLoadCommand((unsigned char *)mmapped, LC_SOURCE_VERSION, NULL);
    struct uuid_command *uuidc = (struct uuid_command *)findLoadCommand((unsigned char *)mmapped, LC_UUID, NULL);

    if (filesize > 2000000)
    {
        xnu = 1;
    }

    if (xnu && svc && (svc->version >> 40) >= 2423)
    {
        if ((svc->version >> 40) >= 3789)
        {
            xnu37xx = 1;
            xnu3757_and_later = 1;

            fprintf(stdout, "This is a %d-bit kernel from %s, or later ",
                    (is64 ? 64 : 32),
                    (iOS ? "iOS 10.x (b7+)" : "OS X (Sorry, \"MacOS\" 10.12b7)"));
        }
        else if ((svc->version >> 40) >= 3777)
        {
            xnu37xx = 1;
            xnu3757_and_later = 1;

            fprintf(stdout, "This is a %d-bit kernel from %s, or later ",
                    (is64 ? 64 : 32),
                    (iOS ? "iOS 10.x (b3+)" : "OS X (Sorry, \"MacOS\" 10.12b3)"));
        }

        else if ((svc->version >> 40) >= 3757)
        {

            xnu37xx = 1;
            xnu3757_and_later = 1;

            fprintf(stdout, "This is a %d-bit kernel from %s, or later ",
                    (is64 ? 64 : 32),
                    (iOS ? "iOS 10.x (b2+)" : "OS X (Sorry, \"MacOS\" 10.12)"));
        }
        else if ((svc->version >> 40) >= 3705)
        {
            xnu37xx = 1;
            fprintf(stdout, "This is a %d-bit kernel from %s, or later ",
                    (is64 ? 64 : 32),
                    (iOS ? "iOS 10.x" : "OS X (Sorry, \"MacOS\" 10.12)"));
        }
        else if ((svc->version >> 40) >= 3216)
        {
            xnu32xx = 1;
            fprintf(stdout, "This is a %d-bit kernel from %s, or later ",
                    (is64 ? 64 : 32),
                    (iOS ? "iOS 9.x" : "OS X 10.11"));
        }
        else if ((svc->version >> 40) >= 2780)
        {
            fprintf(stdout, "This is a %d-bit kernel from %s, or later ",
                    (is64 ? 64 : 32),
                    (iOS ? "iOS 8.x" : "OS X 10.10"));
            xnu27xx = 1;
        }
        else

            xnu24xx = 1;
    }

    //else this is a kext
    if (!xnu)
    {
        fprintf(stdout, "This is %s\n", identifyKextNew(mmapped, filesize, mmapped));
    }
    else if (svc)
    {

        fprintf(stdout, "(%ld.%d.%d.%d.%d)\n",
                (long)((svc->version) >> 40),
                (int)(svc->version >> 30) & 0x000003FF,
                (int)(svc->version >> 20) & 0x000003FF,
                (int)(svc->version >> 10) & 0x000003FF,
                (int)(svc->version) & 0x000003FF);
    }
    else
    {
        fprintf(stdout, "(No LC_SOURCE_VERSION.. your dump may be corrupt.. or this might be a really old kernel!)\n");
    }

    if (wantJToolOut)
    {
        extern char *g_fileName;
        g_fileName = filename;
        jtoolOutFD = openCompanionFileName(mmapped, 2);
        if (jtoolOutFD)
            fprintf(stderr, "Opening companion file\n");
    }

    uint32_t numSyms;
    struct symtabent *symTable = MachOGetSymbols(mmapped, filesize, &numSyms); // uint32_t *numsyms)

    //struct symtabent *symTable = NULL;
    if (symTable)
    {
        if (g_jdebug)
            fprintf(stderr, "Got %d syms from kernel\n", numSyms);
        kernelSymTable = symTable;
    }
    else
    {
        if (xnu)
            printf("Unable to get symbols from SYMTAB (fine for dumps)\n");
    }

    int wantDis = 1;
    if (wantDis)
    {
        if (wantJToolOut)
        {

            char *seg = "__TEXT.__text";
            uint64_t addr = MachOGetSectionAddr(mmapped, seg);
            if (!addr)
            {
                seg = "__TEXT_EXEC.__text";
                addr = MachOGetSectionAddr(mmapped, seg);
            }
            uint32_t offset = MachOGetSectionOffset(mmapped, seg);
            uint32_t size = MachOGetSectionOffset(mmapped, seg);

            uint32_t SMC_inst = 0xd4000223;

            uint64_t SMC_inst_addr = look_for_inst("_secure_monitor", SMC_inst, mmapped + offset, size, addr, jtoolOutFD);

            uint32_t start_cpu = 0xd5034fdf; // DAIFSet ... #15
            uint64_t start_cpu_addr = look_for_inst("_start_cpu", start_cpu, mmapped + offset, size, addr, jtoolOutFD);

            register_disassembled_function_call_callback(function_identifier);

            printf("Auto-Disassembling %s from 0x%llx to find rest..\n", seg, addr);
            printf("This may take a little while, but you only need to do this once\n");

            disassemble(mmapped,
                        addr,
                        segments,
                        DISASSEMBLE_QUIET,
                        DISASSEMBLE_END_OF_SECTION);
        }
    }
    //printf ("Entry point is 0x%llx..", getEntryPoint());

    for (i = 0;
         i < filesize - 50;
         i++)
    {
        if (!xnu)
            break;
        if (!xnuSig && memcmp(&mmapped[i], XNUSIG, strlen(XNUSIG)) == 0)
        {

            /* Could actually get the version from LC_SOURCE_VERSION... */

            char buf[80];
            xnuSig = mmapped + i + strlen(XNUSIG);
            memset(buf, '\0', 80);
            strncpy(buf, xnuSig, 40);

            // The signature we get is from a panic, with the full path to the
            // xnu sources. Remove the "/" following the XNU version. Because the
            // memory is mmap(2)ed read only, we have to copy this first.

            char *temp = strstr(buf, "/");
            if (temp)
            {
                *temp = '\0';
            }

            xnuSig = buf;

            if (showVersion)
            {
                printf("This is XNU %s\n", xnuSig);
                exit(0);
            }
        }

        if (memcmp(&mmapped[i], ARMExcVector, 8) == 0)
        {
            sysentAddr = findAddressOfOffset(i - 28);

            if (showUNIX)
                printf("ARM Exception Vector is at file offset @0x%x (Addr: 0x%llx)\n", i - 28, findAddressOfOffset(i - 28));
        }

        int ARM64_exception_vector_base = 0xd5385201;

        if (memcmp(&mmapped[i], &ARM64_exception_vector_base, 4) == 0)
        {
            if (!((i - 8) & 0xfff))
            {
                printf("ARM64 Exception Vector is at file offset @0x%x (Addr: 0x%llx)\n", i - 8, findAddressOfOffset(i - 8));

                if (jtoolOutFD > 0)
                {
                    char output[1024];
                    uint64_t addr = findAddressOfOffset(i - 8);

                    sprintf(output, "0x%llx:ARM64ExceptionVectorBase\n0x%llx:Synchronous_handler\n0x%llx:IRQ_vIRQ_handler\n0x%llx:FIQ_vFIQ\n0x%llx:SError_vSError\n",
                            addr, addr, addr + 0x80, addr + 0x100,
                            addr + 0x180);

                    /*
0x4100003000:synchronous_handler
0x4100003080:IRQ/vIRQ
0x4100003100:FIQ/vFIQ
0x4100003180:SError/vSError
0x4100003200:synchronous_SPx
0x4100003280:IRQ/vIRQ_SPx
0x4100003300:FIQ/vFIQ_SPx
0x4100003380:SError/vSError_SPx
0x4100003400:synchronous_Lower_EL
0x4100003480:IRQ/vIRQ_Lower_EL
0x4100003500:FIQ/vFIQ_SPx
0x4100003580:SError/vSError_Lower_EL
*/
                    write(jtoolOutFD, output, strlen(output));
                    output[0] = '\0';
                }
            }
        }

        if (xnu27xx || xnu32xx || xnu37xx)
        {
            if ((memcmp(&mmapped[i], SIG1_IOS8X, 8) == 0) &&
                (memcmp(&mmapped[i + 0x18], SIG1_AFTER_0x18_IOS8X, 8) == 0))
            {
                sysentAddr = findAddressOfOffset(i - 0x10);

                printf("Found iOS 8+ sysent table @%x (Addr: 0x%llx)\n", i - 0x10, findAddressOfOffset(i - 0x10));
                sysent = mmapped + i - 0x10;
            }
        } // xnu27xx

        else
        {
            if (memcmp(&mmapped[i], SIG1, 20) == 0)
            {
                if (memcmp(&mmapped[i + 24], SIG1_SUF, 16) == 0)
                {
                    sysent = mmapped + i - 24;
                    //		  if (xnuSig) break;
                }
            }

            if ((memcmp(&mmapped[i], SIG1_IOS7X, 16) == 0) &&
                (memcmp(&mmapped[i + 20], SIG2_IOS7X, 16) == 0) &&
                (memcmp(&mmapped[i + 40], SIG1_IOS7X, 16) == 0))
            {
                sysent = mmapped + i - 24;
                //		  if (xnuSig) break;
            }

        } // ! iOS 8

        // Can and should actually rewrite this to a) read from the __const section and b) be 32/64-bit agnostic

    } // end for i..

    if (xnu && !xnuSig)
    {
        fprintf(stderr, "This doesn't seem to be a kernel! Continuing anyway..\n");
    }

    if (!sysent && is64)
    {
        struct section_64 *segDC = MachOGetSection((unsigned char *)"__DATA.__const");
        if (!segDC)
        {
            segDC = MachOGetSection((unsigned char *)"__CONST.__constdata");
        }
        if (!segDC)
        {
            segDC = MachOGetSection((unsigned char *)"__DATA_CONST.__const");
        }

        if (!segDC)
        {
            fprintf(stderr, "No __DATA.__const or CONST?!\n");
            return 0;
        }
        int offset = (is64 ? segDC->offset : segDC->offset);
        int i = 0;
        char *pos = mmapped + offset;

        int adv = 8;

        for (i = 0; i < segDC->size; i += adv)
        {

            if (memcmp(&pos[i], SIG_SYSCALL_3, 8) == 0)
            {
                // if (memcmp (&pos[i] + 0x18, SIG_SYSCALL_3,8) == 0) printf("DOUBLE BINGO\n");
                sysent = pos + i - 0x10 - (3 * 0x18);

                sysentAddr = segDC->addr + i - 0x10 - (3 * 0x18);
                // Can double check since same sig is also at + 0x18 from here..
                // Bingo!
                break;
            }
        }
    }

    if (showMach)
        doMachTraps(mmapped, xnu32xx || xnu37xx);
    if (showMach)
        doMIG(mmapped, xnu32xx || xnu37xx);

    if (showUNIX && sysent)
    {
        if (memcmp(&mmapped[i], "syscall\0exit", 12) == 0)
        {
            //	syscall_names = &mmapped[i];

            printf("Syscall names are @%x\n", i);
        }

        printf("Syscalls at address 0x%llx\n", sysentAddr);

        if (is64)
            printf("Sysent offset in file (for patching purposes):  %lx\n", (sysent - mmapped));

        uint64_t enosys, old = 0;

        if (suppressEnosys)
        {
            enosys = (xnu27xx || xnu32xx || xnu37xx) ? *((int *)(sysent + 0x60)) : *((int *)(sysent + 20 + 24 * 4));
            old = (xnu27xx || xnu32xx || xnu37xx) ? *((int *)(sysent + 0x60 + 30 * 12)) : *((int *)(sysent + 20 + 24 * 4));

            if (is64)
            {
                // enosys is at syscall 0
                enosys = *(uint64_t *)sysent;
                // old is at syscall 8

                old = *(((uint64_t *)sysent) + (8 * 0x3));
            }
            printf("Suppressing enosys (%llx) and old (%llx)\n", enosys, old);
        }

        int maxsyscall = SYS_MAXSYSCALL;
        if (xnu24xx)
            maxsyscall = SYS_MAXSYSCALL_7;
        if (xnu27xx)
            maxsyscall = SYS_MAXSYSCALL_8;
        if (xnu32xx)
            maxsyscall = SYS_MAXSYSCALL_9;
        if (xnu37xx)
            maxsyscall = SYS_MAXSYSCALL_10;

        for (i = 0; i < maxsyscall; i++)
        {
            int suppress = 0;
            int thumb = 0;

            int jump = (xnu24xx ? 20 : 24);
            if (xnu27xx || xnu32xx || xnu37xx)
                jump = 12;

            if (is64)
                jump = 0x18;

            uint64_t addr = *((int *)(sysent + 20 + jump * i));

            if (xnu27xx || xnu32xx || xnu37xx)
                addr = *((int *)(sysent + jump * i));

            if (is64)
            {
                addr = *((uint64_t *)(sysent + jump * i));
            }

            if ((addr == enosys) || addr == old)
                suppress = 1;

            if (!is64)
            {
                if ((addr % 4) == 1)
                {
                    addr--;
                    thumb++;
                }
                if ((addr % 4) == -3)
                {
                    addr--;
                    thumb++;
                }
            }

            if (!suppress)
            {
                if (wantJToolOut)
                {

                    char output[1024];
                    sprintf(output, "_%s", syscall_names[i]);

                    addSymbolToCache(output, addr, NULL);
                    //
                    //	 sprintf (output, "0x%llx:_%s\n", addr, syscall_names[i]);
                    // write (jtoolOutFD, output, strlen(output));
                }

                else
                {
                    if (is64)
                    {
                        printf("%d.. %-20s 0x%llx\n", i, syscall_names[i], addr);
                    }
                    else
                        printf("%d. %-20s %x %s\n", i, syscall_names[i], addr, (thumb ? "T" : "-"));
                }

            } // !suppress`

            // skip to next post null byte - unfortunately wont work due to optimizations
            // putting some of the system call name strings elsewhere (in their first appearance
            // in the binary)

            //  for (; *syscall_names; syscall_names++);
            //  syscall_names++;
        }
    } // showUNIX

    // Do KEXTs

    void *seg = MachOGetSection((unsigned char *)"__DATA.__const");

    if (!seg)
        seg = MachOGetSection((unsigned char *)"__CONST.__constdata");
    if (!seg)
    {
        seg = MachOGetSection((unsigned char *)"__DATA_CONST.__const");
    }

    if (!seg)
    {
        fprintf(stderr, "Unable to find const section. This shouldn't be happening.. continuting anyway, but can't look for sysent/mach_trap_table\n");
    }
    else
    {
    }

_sysctls:
    if (showSysctls)
        doSysctls(mmapped, is64);

_kexts:
_kextraction:
    if (kextract || showKexts)
    {
        int meth = 2;
        if (xnu37xx)
        {
            if (g_jdebug)
                fprintf(stderr, "This is a XNU 37xx or later kernel, so defaulting to method #1 (__PRELINK_INFO)\n");
            meth = 1;
            if (getenv("METH2"))
                meth = 2;
        }
        doKexts(mmapped, kextName, meth);
    }

    if (jtoolOutFD)
    {
        char *cfn = getCompanionFileName(mmapped);
        printf("Output written to %s in Jtool-compatible format. Run jtool with --jtooldir . or set JTOOLDIR=\n",
               cfn);

        // merge cache syms

        dumpSymbolCacheToFile(jtoolOutFD);

        close(jtoolOutFD);
    }
}