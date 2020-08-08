// fallback always-fail implementation for platforms without sandboxing
// mechanisms

#include <assert.h>
#include <errno.h>
#include "../plat-run.h"
#include <stddef.h>

int plat_run(const char **argv, const no_config_t *config) {

  assert(argv != NULL);
  assert(argv[0] != NULL);
  assert(config != NULL);

  return ENOTSUP;
}
