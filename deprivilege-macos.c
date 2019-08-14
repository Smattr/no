#include "deprivilege.h"
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __APPLE__
  #include <sandbox.h>
#endif

/* Apple has deprecated the sandboxing functions, but there is no replacement
 * for them
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int deprivilege(bool network) {

  if (!network) {
    char *err = NULL;
    int r = sandbox_init(kSBXProfileNoNetwork, SANDBOX_NAMED, &err);

    if (r != 0) {
      fprintf(stderr, "failed to setup sandbox: %s\n", err);
      sandbox_free_error(err);
      return -1;
    }
  }

  return 0;
}

#pragma clang diagnostic pop
