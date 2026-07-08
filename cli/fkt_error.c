/* fkt_error.c */
#include "fkt_error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FKT_LAST_ERR_MAX 256

static char g_last_error[FKT_LAST_ERR_MAX];

void fkt_fatal(const char *msg) {
    fprintf(stderr, "FKT FATAL: %s\n", msg);
    exit(1);
}

void fkt_last_error_clear(void) {
    g_last_error[0] = '\0';
}

void fkt_last_error_set(const char *msg) {
    if (!msg) {
        g_last_error[0] = '\0';
        return;
    }
    strncpy(g_last_error, msg, FKT_LAST_ERR_MAX - 1);
    g_last_error[FKT_LAST_ERR_MAX - 1] = '\0';
}

const char *fkt_last_error_get(void) {
    return g_last_error;
}