/* test_parse.c - PR4 parser error-path + golden/reject smoke tests */
#include "../fkt_psbt.h"
#include "../fkt_error.h"
#include <stdio.h>
#include <string.h>

/* fkt_memzero.o references this from the SIGINT handler; stub for standalone test. */
void fkt_ui_term_restore(void) {}

static int failures = 0;

static int parse_file(const char *path) {
    fkt_last_error_clear();
    fkt_psbt_init();
    if (fkt_psbt_load_input(path) != 0) {
        fkt_last_error_set("Failed to load PSBT.");
        return -1;
    }
    return fkt_psbt_try_parse();
}

static void expect_parse_ok(const char *name, const char *path) {
    if (parse_file(path) != 0) {
        printf("FAIL %s: %s\n", name, fkt_last_error_get());
        failures++;
        return;
    }
    printf("PASS %s\n", name);
}

static void expect_parse_fail(const char *name, const char *path,
                              const char *substr) {
    const char *err;

    if (parse_file(path) == 0) {
        printf("FAIL %s: expected rejection\n", name);
        failures++;
        return;
    }
    err = fkt_last_error_get();
    if (!err || err[0] == '\0') {
        printf("FAIL %s: missing parse error message\n", name);
        failures++;
        return;
    }
    if (substr != NULL && strstr(err, substr) == NULL) {
        printf("FAIL %s: got '%s' (want substring '%s')\n", name, err, substr);
        failures++;
        return;
    }
    printf("PASS %s (%s)\n", name, err);
}

int main(void) {
    expect_parse_ok("golden p2wpkh 1in1out",
                    "tests/golden-51/unsigned/p2wpkh_all_1in_1out.psbt");
    expect_parse_ok("golden p2tr default",
                    "tests/golden-51/unsigned/p2tr_keypath_default_1in_1out.psbt");
    expect_parse_ok("golden p2wsh 2of3",
                    "tests/golden-51/unsigned/p2wsh_2of3_all_1in_2out.psbt");
    expect_parse_ok("golden nonwitness only",
                    "tests/golden-51/unsigned/p2wpkh_nonwitness_only_1in_2out.psbt");
    expect_parse_ok("synthetic p2wpkh",
                    "tests/synthetic/unsigned/p2wpkh_1in_1out.psbt");
    expect_parse_ok("sparrow p2wpkh 1in1out",
                    "tests/sparrow-real/Unsigned/v1/v1_p2wpkh_1in_1out.psbt");
    expect_parse_ok("sparrow p2tr 1in1out",
                    "tests/sparrow-real/Unsigned/v1/v1_p2tr_1in_1out.psbt");
    expect_parse_ok("sparrow p2wpkh 2in2out",
                    "tests/sparrow-real/Unsigned/v1/v1_p2wpkh_2in_2out.psbt");

    expect_parse_fail("reject unknown key",
                      "tests/synthetic/unsigned/unknown_key.psbt",
                      "Unknown PSBT key");
    expect_parse_fail("reject duplicate outpoint",
                      "tests/synthetic/unsigned/duplicate_outpoint.psbt",
                      "Duplicate outpoint");
    expect_parse_fail("reject sighash none",
                      "tests/synthetic/unsigned/p2wpkh_none.psbt",
                      "SIGHASH_TYPE");
    expect_parse_ok("sparrow both utxos (matching)",
                    "tests/golden-51/unsigned/p2wpkh_both_utxos_1in_2out.psbt");
    expect_parse_fail("reject signed psbt",
                      "tests/golden-51/golden-signed/p2wpkh_all_1in_1out.psbt",
                      "Unknown PSBT key");

    if (failures != 0) {
        printf("\n%d test(s) failed.\n", failures);
        return 1;
    }
    printf("\nAll parse tests passed.\n");
    return 0;
}