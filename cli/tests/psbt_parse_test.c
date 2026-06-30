/* tests/psbt_parse_test.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../fkt_preview.h"

int main(int argc, char *argv[]) {
    int show_preview = 0;
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <psbt_file> [--preview]\n", argv[0]);
        return 2;
    }
    if (argc == 3 && strcmp(argv[2], "--preview") == 0) {
        show_preview = 1;
    }

    if (show_preview) {
        return fkt_psbt_preview(argv[1]) != 0 ? 1 : 0;
    }
    return 0;
}