---
hide_table_of_contents: true
---

# Dump Syscalls

```bash
❯ ipsw kernel syscall 20A5312j__iPhone14,2/kernelcache.release.iPhone14,2 | head
0:   syscall call=0xfffffff0081f28f4 munge=0x0                ret=int      narg=0 (bytes=0)  { int nosys(void); }   { indirect syscall }
1:   exit    call=0xfffffff0081aac70 munge=0xfffffff007ecd07c ret=none     narg=1 (bytes=4)  { void exit(int rval); }
2:   fork    call=0xfffffff0081b265c munge=0x0                ret=int      narg=0 (bytes=0)  { int fork(void); }
3:   read    call=0xfffffff0081f3270 munge=0xfffffff007ecd09c ret=ssize_t  narg=3 (bytes=12) { user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte); }
4:   write   call=0xfffffff0081f40f8 munge=0xfffffff007ecd09c ret=ssize_t  narg=3 (bytes=12) { user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte); }
5:   open    call=0xfffffff007f0bf68 munge=0xfffffff007ecd09c ret=int      narg=3 (bytes=12) { int open(user_addr_t path, int flags, int mode); }
6:   close   call=0xfffffff00818d870 munge=0xfffffff007ecd07c ret=int      narg=1 (bytes=4)  { int sys_close(int fd); }
7:   wait4   call=0xfffffff0081ae384 munge=0xfffffff007ecd0b8 ret=int      narg=4 (bytes=16) { int wait4(int pid, user_addr_t status, int options, user_addr_t rusage); }
8:   enosys  call=0xfffffff0081f28d4 munge=0x0                ret=int      narg=0 (bytes=0)  { int enosys(void); }   { old creat }
9:   link    call=0xfffffff007f0d670 munge=0xfffffff007ecd088 ret=int      narg=2 (bytes=8)  { int link(user_addr_t path, user_addr_t link); }
```
