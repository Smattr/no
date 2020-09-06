#include <assert.h>
#include <crt_externs.h>
#include <errno.h>
#include <no/no.h>
#include "run_with_profile.h"
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

// print a string, escaping regex-sensitive characters
static int fput_escaping(FILE *f, const char *s) {
  assert(f != NULL);
  assert(s != NULL);
  for (; *s != '\0'; ++s) {
    switch (*s) {
      case '\\':
      case '^':
      case '$':
      case '*':
      case '+':
      case '?':
      case '.':
      case '(':
      case ')':
      case '|':
      case '{':
      case '}':
      case '[':
      case ']':
      case '"':
        if (fputc('\\', f) == EOF)
          return -1;
        /* fall through */
      default:
        if (fputc(*s, f) == EOF)
          return -1;
    }
  }
  return 0;
}

int run_with_profile(const char **argv, const no_config_t *config) {

  assert(argv != NULL);
  assert(config != NULL);

  // find TMPDIR
  const char *TMPDIR = getenv("TMPDIR");
  if (TMPDIR == NULL)
    TMPDIR = "/tmp";

  // create a temporary file to write a sandbox profile into
  char *tmp;
  if (asprintf(&tmp, "%s/tmp.XXXXXX", TMPDIR) < 0)
    return errno;
  if (mkstemp(tmp) < 0) {
    free(tmp);
    return errno;
  }

  int ret = 0;

  FILE *profile = fopen(tmp, "w");
  if (profile == NULL) {
    ret = errno;
    goto done;
  }

  // write sandbox profile header
  if (fprintf(profile, "(version 1)\n(allow default)\n") < 0) {
    ret = errno;
    goto done;
  }

  // block networking?
  if (!config->network) {
    if (fprintf(profile, "(deny network*)\n") < 0) {
      ret = errno;
      goto done;
    }
  }

  // block $HOME?
  if (!config->home) {
    // block default home paths
    if (fprintf(profile, "(deny file* (regex \"^/home/.*\"))\n"
                         "(deny file* (regex \"^/Users/.*\"))\n") < 0) {
      ret = errno;
      goto done;
    }

    // block $HOME, which may contain something else like "/root"
    const char *HOME = getenv("HOME");
    if (HOME != NULL) {
      if (fprintf(profile, "(deny file* (regex \"^") < 0
          || fput_escaping(profile, HOME) < 0
          || fprintf(profile, "/.*\"))\n") < 0) {
        ret = errno;
        goto done;
      }
    }
  }

  // block writes?
  if (config->file_system == NO_WRITES) {
    if (fprintf(profile, "(deny file-write*)\n") < 0) {
      ret = errno;
      goto done;
    }

  // block writes except $TMPDIR?
  } else if (config->file_system == NO_WRITES_EXCEPT_TMP) {
    if (fprintf(profile, "(deny file-write* (regex \"^(?!") < 0
        || fput_escaping(profile, TMPDIR) < 0
        || fprintf(profile, ")\"))\n") < 0) {
      ret = errno;
      goto done;
    }
  }

  (void)fclose(profile);
  profile = NULL;

  // calculate number of command arguments we have
  size_t argc = 0;
  while (argv[argc] != NULL)
    ++argc;

  // allocate space to construct a command line to run our command via
  // sandbox-exec
  const char **args = calloc(argc + 4, sizeof(args[0]));
  if (args == NULL) {
    ret = ENOMEM;
    goto done;
  }

  // construct the actual invocation
  args[0] = "sandbox-exec";
  args[1] = "-f";
  args[2] = tmp;
  for (size_t i = 3; i < argc + 3; ++i)
    args[i] = argv[i - 3];
  // final array entry is already NULL

  // run this command
  pid_t pid;
  ret = posix_spawnp(&pid, args[0], NULL, NULL, (char*const*)args,
    *_NSGetEnviron());

  // we no longer need the command
  free(args);

  // if we started the process, wait for it to complete
  if (ret == 0) {
    (void)waitpid(pid, &ret, 0);

    (void)unlink(tmp);
    free(tmp);

    // caller expects us to have exec()ed, so replicate that
    if (WIFEXITED(ret)) {
      ret = WEXITSTATUS(ret);
    } else if (WIFSIGNALED(ret)) {
      (void)raise(WTERMSIG(ret));
    }
    exit(ret);
  }

done:
  if (profile != NULL)
    (void)fclose(profile);
  (void)unlink(tmp);
  free(tmp);

  return ret;
}
