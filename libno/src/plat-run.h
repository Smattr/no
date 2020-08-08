#pragma once

#include <no/no.h>

/** platform-specific implementation of no_run
 *
 * \param argv NULL-terminated argument vector
 * \param options Sandbox configuration
 * \return An errno on failure
 */
__attribute__((visibility("internal")))
int plat_run(const char **argv, const no_config_t *config);
