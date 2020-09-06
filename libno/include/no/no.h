#pragma once

#include <stdbool.h>

#ifdef __cplusplus
  extern "C" {
#endif

/// access permissions for file system operations
typedef enum {

  /// read-only
  NO_WRITES,

  /// read-only, except allow writes to $TMPDIR
  NO_WRITES_EXCEPT_TMP,

  /// full read/write
  NO_RESTRICTIONS,

} no_access_t;

/// configuration for sandboxing
typedef struct {

  /// allow network access?
  bool network;

  /// allow access to $HOME?
  bool home;

  /// file system access permissions
  no_access_t file_system;

  /// debug mode (verbose denial reporting)
  bool debug;

} no_config_t;

/** replace our image with the given program in a sandbox
 *
 * \param argv NULL-terminated argument vector
 * \param options Sandbox configuration
 * \return An errno on failure
 */
int no_run(const char **argv, const no_config_t *config);

#ifdef __cplusplus
}
#endif
