#include <getopt.h>
#include <no/no.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
    #include <crt_externs.h>
#endif

static char **get_environ(void) {
#ifdef __APPLE__
  // on macOS, environ is not directly accessible
  return *_NSGetEnviron();
#else
  /* some platforms fail to expose environ in a header (e.g. FreeBSD), so
   * declare it ourselves and assume it will be available when linking
   */
  extern char **environ;

  return environ;
#endif
}

static void help() {

  // man page data that is generated
  extern unsigned char no_1[];
  extern unsigned int no_1_len;

  // find $TMPDIR
  const char *TMPDIR = getenv("TMPDIR");
  if (TMPDIR == NULL)
    TMPDIR = "/tmp";

  // create a temporary file
  char *path = NULL;
  if (asprintf(&path, "%s/temp.XXXXXX", TMPDIR) < 0) {
    perror("asprintf");
    exit(EXIT_FAILURE);
  }
  int fd = mkstemp(path);
  if (fd < 0) {
    perror("mkstemp");
    free(path);
    exit(EXIT_FAILURE);
  }

  // write the manpage to the temporary file
  {
    size_t len = no_1_len;
    for (const unsigned char *p = no_1; len > 0; ) {
      ssize_t r = write(fd, p, len);
      if (r < 0) {
        close(fd);
        perror("write");
        (void)unlink(path);
        free(path);
        exit(EXIT_FAILURE);
      }
      p += (size_t)r;
      len -= (size_t)r;
    }
    close(fd);
  }

  // run man to display the help text
  const char *argv[] = { "man",
#ifdef __linux__
    "--local-file",
#endif
    path, NULL };
  int ret = EXIT_FAILURE;
  do {

    pid_t pid;
    int r = posix_spawnp(&pid, argv[0], NULL, NULL, (char*const*)argv,
      get_environ());
    if (r != 0) {
      fprintf(stderr, "posix_spawnp: %s\n", strerror(r));
      break;
    }

    int status;
    if (waitpid(pid, &status, 0) < 0) {
      perror("waitpid");
      break;
    }

    if (WIFEXITED(status))
      ret = WEXITSTATUS(status);

  } while (0);

  // clean up
  (void)unlink(path);
  free(path);

  exit(ret);
}

static no_config_t conf = {
  .home_read = true,
  .home_write = true,
  .temp_write = true,
  .rest_write = true,
};

static char **args;

static void parse_args(int argc, char **argv) {

  for (;;) {

    static const struct option opts[] = {
      { "allow-network", no_argument, 0, 128 },
      { "disallow-network", no_argument, 0, 129 },
      { "help", no_argument, 0, 'h' },
      { 0, 0, 0, 0 },
    };

    int option_index = 0;
    int c = getopt_long(argc, argv, "", opts, &option_index);

    if (c == -1)
      break;

    switch (c) {

      case '?': // illegal option
        exit(EXIT_FAILURE);

      case 'h': // --help
        help();
        __builtin_unreachable();

      case 128: // --allow-network
        conf.network = true;
        break;

      case 129: // --disallow-network
        conf.network = false;
        break;

    }
  }

  args = &argv[optind];
}

int main(int argc, char **argv) {

  // parse command line options
  parse_args(argc, argv);

  if (args == NULL || *args == NULL) {
    fprintf(stderr, "no command provided\n");
    return EXIT_FAILURE;
  }

  int err = no_run((const char**)args, &conf);
  if (err != 0) {
    fprintf(stderr, "no_run failed: %s\n", strerror(err));
    return EXIT_FAILURE;
  }

  return EXIT_FAILURE;
}
