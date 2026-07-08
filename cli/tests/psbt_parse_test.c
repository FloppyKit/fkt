/* psbt_parse_test.c - slim parse-only CLI for run_parser_tests.py */
#include <stdio.h>
#include <stdlib.h>
#include "../fkt_psbt.h"
#include "../fkt_error.h"

void fkt_ui_term_restore(void) {}

int main(int argc, char *argv[]) {
    const char *path;
    const char *err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <psbt_file>\n", argv[0]);
        return 2;
    }
    path = argv[1];

    fkt_last_error_clear();
    fkt_psbt_init();
    if (fkt_psbt_load_input(path) != 0) {
        fprintf(stderr, "Failed to load PSBT file.\n");
        return 1;
    }
    if (fkt_psbt_try_parse() != 0) {
        err = fkt_last_error_get();
        if (err && err[0] != '\0')
            fprintf(stderr, "%s\n", err);
        else
            fprintf(stderr, "PSBT parse failed.\n");
        return 1;
    }
    return 0;
}