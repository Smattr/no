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

  return plat_run(argv, config);
}
