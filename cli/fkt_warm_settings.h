/* fkt_warm_settings.h – Warm autoload path (not for Ice Cold). */
#ifndef FKT_WARM_SETTINGS_H
#define FKT_WARM_SETTINGS_H

#include "fkt_compat.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FKT_WARM_SETTINGS_DEFAULT "fkt-warm.conf"
#define FKT_WARM_PATH_MAX 512

/* Load autoload_seed= line from path (or FKT_WARM_SETTINGS env, or default). */
int fkt_warm_settings_load(const char *settings_path,
                           char *autoload_out, size_t autoload_max);

/* Write/update autoload_seed= in settings file. */
int fkt_warm_settings_set_autoload(const char *settings_path,
                                   const char *seed_file_path);

#ifdef __cplusplus
}
#endif
#endif
