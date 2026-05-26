/* tests/psbt_parse_test.c
 * Minimal harness for the FKT PSBT parser.
 * Compile from project root:
 *   gcc -std=c89 -O0 -g -Wall -Wextra -o psbt_parse_test tests/psbt_parse_test.c cli/fkt_psbt.c -I.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include path relative to the tests/ directory (works when compiling from project root with -I.) */
#include "../cli/fkt_psbt.h"

int main(int argc, char *argv[]) {
    int show_preview = 0;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <psbt_file> [--preview]\n", argv[0]);
        return 2;
    }

    if (argc == 3 && strcmp(argv[2], "--preview") == 0) {
        show_preview = 1;
    }

    fkt_psbt_init();

    if (fkt_psbt_load_file(argv[1]) != 0) {
        fprintf(stderr, "Error loading PSBT file: %s\n", argv[1]);
        return 1;
    }

    fkt_psbt_parse();   /* may call fkt_psbt_die() -> exit(1) */

    if (show_preview) {
        fkt_psbt_preview();   /* prints to stdout */
    }

    return 0;
}
