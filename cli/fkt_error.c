/* fkt_error.c */
#include "fkt_error.h"
#include <stdio.h>
#include <stdlib.h>

void fkt_fatal(const char *msg) {
    fprintf(stderr, "FKT FATAL: %s\n", msg);
    exit(1);
}