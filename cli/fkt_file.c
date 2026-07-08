/* fkt_file.c - portable file metadata checks */
#define _POSIX_C_SOURCE 200809L

#include "fkt_platform.h"
#include <sys/stat.h>

int fkt_file_is_regular(const char *path) {
    struct stat st;

    if (!path || path[0] == '\0')
        return 0;
    if (stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) ? 1 : 0;
}