// initial entry point for no_run() to avoid each platform implementation having
// to repeat pre-condition checks

#include <errno.h>
#include <no/no.h>
#include "plat-run.h"
#include <stddef.h>

int no_run(const char **argv, const no_config_t *config) {

  if (argv == NULL)
    return EINVAL;

  if (argv[0] == NULL)
    return EINVAL;

  if (config == NULL)
    return EINVAL;

  // enabling $HOME writing but not reading is not supported
  if (config->home_write && !config->home_read)
    return EINVAL;

  return plat_run(argv, config);
}
