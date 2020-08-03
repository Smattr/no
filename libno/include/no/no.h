#pragma once

#include <stdbool.h>

/// configuration for sandboxing
typedef struct {

  /// allow network access?
  bool network;

} no_config_t;

/** replace our image with the given program in a sandbox
 *
 * \param argv NULL-terminated argument vector
 * \param options Sandbox configuration
 * \return An errno on failure
 */
int no_run(const char **argv, const no_config_t *config);
