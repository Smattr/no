#include <assert.h>
#include <errno.h>
#include "../plat-run.h"
#include <sandbox.h>
#include <stddef.h>
#include <unistd.h>

int plat_run(const char **argv, const no_config_t *config) {

  assert(argv != NULL);
  assert(argv[0] != NULL);
  assert(config != NULL);

  // TODO: implement other restrictions
  if (!config->home || config->file_system != NO_RESTRICTIONS)
    return ENOTSUP;

  // can we use the built-in "no network" profile?
  if (!config->network) {
    char *err;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (sandbox_init(kSBXProfileNoNetwork, SANDBOX_NAMED, &err) != 0) {
      sandbox_free_error(err);
#pragma clang diagnostic pop
      return ENOSYS;
    }
  }

  (void)execvp(argv[0], (char*const*)argv);

  // if we reached here, an error occurred
  return errno;
}
