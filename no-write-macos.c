#include <errno.h>
#include <sandbox.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Apple has deprecated the sandboxing functions, but there is no replacement
 * for them
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int main(int argc, char **argv) {

  char *err = NULL;

  /* valid we have a command */
  if (argc == 1 || strcmp(argv[1], "--help") == 0) {
    fprintf(stderr, "usage: %s command args...\n"
                    " prevent a process from writing to the file system\n", argv[0]);
    return EXIT_FAILURE;
  }
  
  /* deny ourselves file writing */
  if (sandbox_init(kSBXProfileNoWrite, SANDBOX_NAMED, &err) != 0) {
    fprintf(stderr, "failed to setup sandbox: %s\n", err);
      sandbox_free_error(err);
      return EXIT_FAILURE;
  }

  /* become the new process */
  (void)execvp(argv[1], argv + 1);

  /* execvp failed */
  fprintf(stderr, "exec failed: %s\n", strerror(errno));

  return EXIT_FAILURE;
}

#pragma clang diagnostic pop
