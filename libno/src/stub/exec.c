// fallback always-fail implementation for platforms without sandboxing
// mechanisms

#include <errno.h>
#include <no/no.h>
#include <stddef.h>

int no_run(const char **argv, const no_config_t *config) {

  if (argv == NULL)
    return EINVAL;

  if (config == NULL)
    return EINVAL;

  return ENOTSUP;
}
