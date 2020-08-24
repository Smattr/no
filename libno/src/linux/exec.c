#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "../plat-run.h"
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int plat_run(const char **argv, const no_config_t *config) {

  assert(argv != NULL);
  assert(argv[0] != NULL);
  assert(config != NULL);

  // TODO: implement other restrictions
  if (!config->home || config->file_system == NO_WRITES_EXCEPT_TMP)
    return ENOTSUP;

  if (!config->network) {

    // disable setting any new privileges via execve etc
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
      return errno;

    // A BPF program that disallows networking calls
    static struct sock_filter filter[] = {

      // load syscall number
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),

      // block calls that can create a socket
#ifdef __NR_socket
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_socket, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_socketcall
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_socketcall, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_socketpair
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_socketpair, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif

      // allow anything else
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };

    static const struct sock_fprog prog = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
    };

    // apply this filter to ourselves
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0))
      return errno;
  }

  if (config->file_system == NO_WRITES) {

    // disable setting any new privileges via execve etc
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
      return errno;

    // A BPF program that disallows anything that causes a file system write
    static struct sock_filter filter[] = {

      // load syscall number
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),

      // block open with write access
#ifdef __NR_open
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open, 0, 6),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_WRONLY, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_RDWR, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
#endif
      // block openat with write access
#ifdef __NR_openat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_openat, 0, 6),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_WRONLY, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_RDWR, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
#endif
#ifdef __NR_open_by_handle_at
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open_by_handle_at, 0, 6),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[2])),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_WRONLY, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_RDWR, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
#endif
#ifdef __NR_chmod
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_chmod, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_chown
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_chown, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_chroot
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_chroot, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_creat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_creat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_fchmodat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_fchmodat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_fchownat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_fchownat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_futimesat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_futimesat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_lchown
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_lchown, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_link
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_link, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_linkat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_linkat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_lremovexattr
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_lremovexattr, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_lsetxattr
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_lsetxattr, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_mkdir
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mkdir, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_mkdirat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mkdirat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_mknod
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mknod, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_mknodat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mknodat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_mount
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_mount, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_pivot_root
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_pivot_root, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_removexattr
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_removexattr, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_rename
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_rename, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_renameat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_renameat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_rmdir
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_rmdir, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_setxattr
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_setxattr, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_symlink
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_symlink, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_symlinkat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_symlinkat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_truncate
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_truncate, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_umount2
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_umount2, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_unlink
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_unlink, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_unlinkat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_unlinkat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_utime
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_utime, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_utimensat
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_utimensat, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_utimes
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_utimes, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
#endif

      // allow anything else
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };

    static const struct sock_fprog prog = {
      .len = sizeof(filter) / sizeof(filter[0]),
      .filter = filter,
    };

    // apply this filter to ourselves
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0))
      return errno;
  }

  (void)execvp(argv[0], (char*const*)argv);

  // if we reached here, an error occurred
  return errno;
}
