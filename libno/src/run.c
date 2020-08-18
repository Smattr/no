// initial entry point for no_run() to avoid each platform implementation having
// to repeat pre-condition checks

#include <errno.h>
#include <no/no.h>
#include "plat-run.h"
#include <stddef.h>
#include <unistd.h>

int no_run(const char **argv, const no_config_t *config) {

  if (argv == NULL)
    return EINVAL;

  if (argv[0] == NULL)
    return EINVAL;

  if (config == NULL)
    return EINVAL;

  // if the user requested no limitations, then we can just exec uninstrumented
  if (config->network && config->home
      && config->file_system == NO_RESTRICTIONS) {
    (void)execvp(argv[0], (char*const*)argv);

    return errno;
  }

  return plat_run(argv, config);
}
