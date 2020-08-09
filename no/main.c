#include <getopt.h>
#include <no/no.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
      { 0, 0, 0, 0 },
    };

    int option_index = 0;
    int c = getopt_long(argc, argv, "", opts, &option_index);

    if (c == -1)
      break;

    switch (c) {

      case '?': // illegal option
        exit(EXIT_FAILURE);

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
