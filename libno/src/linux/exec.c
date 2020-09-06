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

// seccomp sequence to permit the given system call
#define ALLOW(syscall) \
  BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, (syscall), 0, 1), \
  BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),

int plat_run(const char **argv, const no_config_t *config) {

  assert(argv != NULL);
  assert(argv[0] != NULL);
  assert(config != NULL);

  // TODO
  if (config->debug)
    return ENOTSUP;

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

      // allow innocuous system calls
      #define X(syscall) ALLOW(syscall)
      #include "syscall-always-allowed.h"
      #undef X

      // allow open() and friends
      #define X(syscall) ALLOW(syscall)
      #include "syscall-open.h"
      #undef X

      // deny anything else
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
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

      // allow innocuous system calls
      #define X(syscall) ALLOW(syscall)
      #include "syscall-always-allowed.h"
      #undef X

      // allow networking system calls
      #define X(syscall) ALLOW(syscall)
      #include "syscall-net.h"
      #undef X

      // block open with write access, allow with read access
#ifdef __NR_open
      BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_open, 0, 6),
      BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[1])),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_WRONLY, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, O_RDWR, 0, 1),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
#endif
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

      // deny anything else
      BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP),
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
