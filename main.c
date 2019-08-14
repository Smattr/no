#include "deprivilege.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* allow network access? */
static bool network = true;

static bool streq(const char *s1, const char *s2) {
  return strcmp(s1, s2) == 0;
}

static size_t parse_options(size_t argc, char **argv) {
  size_t i;

  for (i = 1; i < argc; i++) {

    if (streq(argv[i], "--network")) {
      if (i == argc - 1) {
        fprintf(stderr, "option --network requires an argument\n");
        exit(EXIT_FAILURE);
      }
      i++;
      if (streq(argv[i], "on")) {
        network = true;
      } else if (streq(argv[i], "off")) {
        network = false;
      } else {
        fprintf(stderr, "invalid argument \"%s\" to --network\n", argv[i]);
        exit(EXIT_FAILURE);
      }
    }

    else {
      /* if this argument was unrecognised, assume it's the start of the command
       * we're wrapping
       */
      break;
    }
  }

  return i;
}

int main(int argc, char **argv) {

  size_t command_index;

  command_index = parse_options((size_t)argc, argv);

  if (command_index == (size_t)argc) {
    fprintf(stderr, "no command provided\n");
    return EXIT_FAILURE;
  }

  if (deprivilege(network) != 0) {
    return EXIT_FAILURE;
  }

  (void)execvp(argv[command_index], argv + command_index);

  /* execvp failed */
  fprintf(stderr, "exec failed: %s\n", strerror(errno));

  return EXIT_FAILURE;
}
