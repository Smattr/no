#include <assert.h>
#include <errno.h>
#include "../plat-run.h"
#include "run_with_profile.h"
#include <sandbox.h>
#include <stddef.h>
#include <unistd.h>

int plat_run(const char **argv, const no_config_t *config) {

  assert(argv != NULL);
  assert(argv[0] != NULL);
  assert(config != NULL);

  // can we use the built-in “no network” profile?
  if (!config->network && config->home
      && config->file_system == NO_RESTRICTIONS) {
    char *err;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (sandbox_init(kSBXProfileNoNetwork, SANDBOX_NAMED, &err) != 0) {
      sandbox_free_error(err);
#pragma clang diagnostic pop
      return ENOSYS;
    }

  // can we use the built-in “no write” profile?
  } else if (config->network && config->home
      && config->file_system == NO_WRITES) {
    char *err;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (sandbox_init(kSBXProfileNoWrite, SANDBOX_NAMED, &err) != 0) {
      sandbox_free_error(err);
#pragma clang diagnostic pop
      return ENOSYS;
    }

  // can we use the built-in “no write except temporary” profile?
  } else if (config->network && config->home
      && config->file_system == NO_WRITES_EXCEPT_TMP) {
    char *err;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (sandbox_init(kSBXProfileNoWriteExceptTemporary, SANDBOX_NAMED, &err)
        != 0) {
      sandbox_free_error(err);
#pragma clang diagnostic pop
      return ENOSYS;
    }

  // otherwise we need to build a custom profile for this
  } else {
    return run_with_profile(argv, config);
  }

  (void)execvp(argv[0], (char*const*)argv);

  // if we reached here, an error occurred
  return errno;
}
