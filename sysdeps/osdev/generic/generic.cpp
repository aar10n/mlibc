#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <dirent.h>
#include <fcntl.h>
#include <osdev/syscalls.h>
#include <cstddef>

#define IS_ERROR(x) ((int64_t)(x) < 0)
#define TO_ERRNO(x) (-(int)((int64_t)(x)))

namespace mlibc {

  void sys_libc_log(const char *message) {
    _syscall(SYS_LOG, message);
  }

  void sys_libc_panic() {
    // mlibc::infoLogger() << "\e[31mmlibc: panic!" << frg::endlog;
    _syscall(SYS_PANIC, "");
    while (true) {}
  }

  int sys_tcb_set(void *pointer) {
    int res = _syscall(SYS_SET_FS_BASE, pointer);
    return res;
  }

  int sys_anon_allocate(size_t size, void **pointer) {
    void *res = (void *) _syscall(SYS_MMAP, NULL, size, PROT_WRITE, MAP_ANON, -1, 0);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }

    *pointer = res;
    return 0;
  }

  int sys_anon_free(void *pointer, size_t size) {
    int res = _syscall(SYS_MUNMAP, pointer, size);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }
    return 0;
  }

#ifndef MLIBC_BUILDING_RTDL
  void sys_exit(int status) {
    _syscall(SYS_EXIT, status);
  }
#endif

#ifndef MLIBC_BUILDING_RTDL
  int sys_clock_get(int clock, time_t *secs, long *nanos) {
    return 0;
  }
#endif

  int sys_open(const char *path, int flags, mode_t mode, int *fd) {
    int res = _syscall(SYS_OPEN, path, flags, mode);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }

    *fd = res;
    return 0;
  }

  int sys_close(int fd) {
    int res = _syscall(SYS_CLOSE, fd);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }
    return 0;
  }

  int sys_read(int fd, void *buf, size_t count, ssize_t *bytes_read) {
    ssize_t res = _syscall(SYS_READ, fd, buf, count);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }

    *bytes_read = res;
    return 0;
  }

#ifndef MLIBC_BUILDING_RTDL
  int sys_write(int fd, const void *buf, size_t count, ssize_t *bytes_written) {
    ssize_t res = _syscall(SYS_WRITE, fd, buf, count);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }

    *bytes_written = res;
    return 0;
  }
#endif


  int sys_seek(int fd, off_t offset, int whence, off_t *new_offset) {
    off_t res = _syscall(SYS_LSEEK, fd, offset, whence);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }

    *new_offset = res;
    return 0;
  }

  int sys_vm_map(void *hint, size_t size, int prot, int flags,
                 int fd, off_t offset, void **window) {
    void *res = (void *) _syscall(SYS_MMAP, hint, size, prot, flags, fd, offset);
    if (IS_ERROR(res)) {
      return TO_ERRNO(res);
    }

    *window = res;
    return 0;
  }

  int sys_vm_unmap(void *pointer, size_t size) {
    return sys_anon_free(pointer, size);
  }

  int sys_futex_wait(int *pointer, int expected, const struct timespec *time) {
    uint64_t err;
    asm volatile ("syscall"
    : "=d"(err)
    : "a"(66), "D"(pointer), "S"(expected)
    : "rcx", "r11");

    if (err) {
      return -1;
    }

    return 0;
  }

  int sys_futex_wake(int *pointer) {
    uint64_t err;
    asm volatile ("syscall"
    : "=d"(err)
    : "a"(65), "D"(pointer)
    : "rcx", "r11");

    if (err) {
      return -1;
    }

    return 0;
  }

// All remaining functions are disabled in ldso.
#ifndef MLIBC_BUILDING_RTDL

  int sys_clone(void *entry, void *user_arg, void *tcb, pid_t *tid_out) {
    void *sp = prepare_stack(entry, user_arg, tcb);
    int tid;

    asm volatile ("syscall"
    : "=a"(tid)
    : "a"(67), "D"(__mlibc_start_thread), "S"(sp), "d"(tcb)
    : "rcx", "r11");

    if (tid_out)
      *tid_out = tid;

    return 0;
  }

  void sys_thread_exit() {
    _syscall(SYS_EXIT, 0);
    __builtin_trap();
  }

  int sys_sleep(time_t *secs, long *nanos) {
    long ms = (*nanos / 1000000) + (*secs * 1000);
    asm volatile ("syscall"
    :
    : "a"(6), "D"(ms)
    : "rcx", "r11");
    *secs = 0;
    *nanos = 0;
    return 0;
  }

  int sys_fork(pid_t *child) {
    pid_t ret;
    int sys_errno;

    asm volatile ("syscall"
    : "=a"(ret), "=d"(sys_errno)
    : "a"(57)
    : "rcx", "r11");

    if (ret == -1)
      return sys_errno;

    *child = ret;
    return 0;
  }

  int sys_execve(const char *path, char *const argv[], char *const envp[]) {
    int ret;
    int sys_errno;

    asm volatile ("syscall"
    : "=a"(ret), "=d"(sys_errno)
    : "a"(59), "D"(path), "S"(argv), "d"(envp)
    : "rcx", "r11");

    if (sys_errno != 0)
      return sys_errno;

    return 0;
  }

  pid_t sys_getpid() {
    pid_t pid;
    asm volatile ("syscall" : "=a"(pid)
    : "a"(5)
    : "rcx", "r11", "rdx");
    return pid;
  }
  pid_t sys_getppid() {
    pid_t ppid;
    asm volatile ("syscall" : "=a"(ppid)
    : "a"(14)
    : "rcx", "r11", "rdx");
    return ppid;
  }

#endif // MLIBC_BUILDING_RTDL

} // namespace mlibc
