/* fkt_warm_settings.c – minimal text settings for Warm ritual machines. */
#include "fkt_warm_settings.h"
#include "fkt_error.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *fkt_warm_settings_path(const char *override_path) {
    const char *env;
    if (override_path && override_path[0])
        return override_path;
    env = getenv("FKT_WARM_SETTINGS");
    if (env && env[0])
        return env;
    return FKT_WARM_SETTINGS_DEFAULT;
}

int fkt_warm_settings_load(const char *settings_path,
                           char *autoload_out, size_t autoload_max) {
    FILE *f;
    char line[FKT_WARM_PATH_MAX + 64];
    const char *path;

    if (!autoload_out || autoload_max < 2)
        return -1;
    autoload_out[0] = '\0';
    path = fkt_warm_settings_path(settings_path);

    f = fopen(path, "r");
    if (!f)
        return 0; /* no settings file = no autoload */

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        size_t n;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;
        if (strncmp(p, "autoload_seed=", 14) == 0) {
            p += 14;
            n = strlen(p);
            while (n > 0 && (p[n - 1] == '\n' || p[n - 1] == '\r' ||
                             p[n - 1] == ' ' || p[n - 1] == '\t'))
                p[--n] = '\0';
            if (n >= autoload_max)
                n = autoload_max - 1;
            memcpy(autoload_out, p, n);
            autoload_out[n] = '\0';
            break;
        }
    }
    fclose(f);
    return 0;
}

int fkt_warm_settings_set_autoload(const char *settings_path,
                                   const char *seed_file_path) {
    FILE *f;
    const char *path;

    if (!seed_file_path || !seed_file_path[0]) {
        fkt_last_error_set("warm settings: empty seed path.");
        return -1;
    }
    path = fkt_warm_settings_path(settings_path);
    f = fopen(path, "w");
    if (!f) {
        fkt_last_error_set("warm settings: cannot write settings file.");
        return -1;
    }
    fprintf(f, "# FKT Warm settings — ritual/education machines only\n");
    fprintf(f, "# NOT for real keys on untrusted hosts.\n");
    fprintf(f, "autoload_seed=%s\n", seed_file_path);
    fclose(f);
    fprintf(stderr, "WARM: wrote %s (autoload_seed=%s)\n", path, seed_file_path);
    return 0;
}
