#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <no/no.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int no_run(const char **argv, const no_config_t *config) {

  if (argv == NULL)
    return EINVAL;

  if (config == NULL)
    return EINVAL;

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

  (void)execvp(argv[0], (char*const*)argv);

  // if we reached here, an error occurred
  return errno;
}
