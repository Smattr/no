#pragma once

#include <no/no.h>

/// implementation of no_run() using custom macOS sandbox profiles
__attribute__((visibility("internal")))
int run_with_profile(const char **argv, const no_config_t *config);
