/* fkt_fuzz.c – libFuzzer / AFL / corpus smoke harness for FKT PSBT pipeline */
#define _POSIX_C_SOURCE 200809L
#include "fkt_psbt.h"
#include "fkt_confirm.h"
#include "fkt_sighash.h"
#include "fkt_signer.h"
#include "fkt_finalizer.h"
#include "fkt_secp256k1.h"
#include "fkt_memzero.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>

#define FKT_FUZZ_MAX_INPUT 4096

/* Sparrow P2WPKH testnet seed (64-byte BIP39 seed, hex) */
static const uint8_t FKT_FUZZ_SEED[64] = {
    0x46,0xb6,0xb7,0x1e,0x4a,0x52,0xba,0x62,0x59,0xaa,0xe7,0xa9,0xea,0xa9,0x91,0xae,
    0xa0,0x7f,0xea,0xd2,0x85,0x0c,0xb9,0x71,0x0a,0xea,0x4b,0x23,0x4b,0x73,0xdc,0xcc,
    0x26,0xf2,0x1d,0x98,0x69,0x24,0xec,0x42,0x24,0xf0,0xff,0xf3,0xb2,0xc7,0x37,0x88,
    0xde,0x8e,0x1f,0x92,0x54,0x51,0xb7,0x9f,0xcc,0xcb,0xed,0x99,0x51,0xb9,0xb1,0x84
};

/* golden-51 xfail oracle: must NOT sign successfully in V1 */
static const char *const fkt_xfail_cases[] = {
    "p2wpkh_none_1in_2out",
    "p2wpkh_all_acp_1in_2out",
    "p2tr_keypath_none_1in_2out",
    "p2tr_keypath_all_acp_1in_2out",
    "p2sh_p2wpkh_all_1in_2out",
    "p2sh_p2wpkh_all_2in_2out",
    "p2sh_p2wpkh_single_1in_2out",
    "p2sh_p2wpkh_all_acp_1in_2out",
    "p2sh_p2wpkh_locktime_1in_2out",
    "p2wsh_1of1_all_1in_2out",
    "p2wsh_2of2_all_1in_2out",
    "p2wsh_2of3_all_1in_2out",
    "p2wsh_3of5_all_1in_2out",
    "p2wsh_2of3_all_2in_2out",
    "p2wsh_2of3_single_1in_2out",
    "p2wsh_2of3_all_acp_1in_2out",
    "p2wsh_2of3_all_3in_2out",
    "p2sh_p2wsh_1of1_all_1in_2out",
    "p2sh_p2wsh_2of2_all_1in_2out",
    "p2sh_p2wsh_2of3_all_1in_2out",
    "p2sh_p2wsh_2of3_all_2in_2out",
    "p2sh_p2wsh_2of3_single_1in_2out",
    "mixed_p2wpkh_p2sh_p2wpkh_2in_2out",
    "mixed_p2wsh_p2tr_2in_2out",
    "mixed_p2sh_p2wpkh_p2tr_2in_2out"
};

static const char *fkt_golden_unsigned_dir = "tests/golden-51/unsigned";

static int fkt_fuzz_quiet_begin(void) {
    fflush(stdout);
    return dup(STDOUT_FILENO);
}

static void fkt_fuzz_quiet_end(int saved_stdout) {
    fflush(stdout);
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);
}

static int fkt_fuzz_one_input(const uint8_t *data, size_t size) {
    uint8_t seed_copy[64];
    int parsed;
    int saved_out;

    if (size == 0 || size > FKT_FUZZ_MAX_INPUT)
        return 0;

    fkt_confirm_set_enabled(0);
    saved_out = fkt_fuzz_quiet_begin();
    freopen("/dev/null", "w", stdout);

    fkt_psbt_init();
    if (fkt_psbt_load_memory(data, size) != 0)
        goto done;
    fkt_psbt_lenient_parse = 1;
    parsed = fkt_psbt_try_parse();
    fkt_psbt_lenient_parse = 0;
    if (parsed != 0)
        goto done;

    fkt_compute_hash_caches();
    memcpy(seed_copy, FKT_FUZZ_SEED, 64);
    (void)fkt_sign_loaded_psbt(seed_copy, "", NULL, "/dev/null");
    fkt_memzero(seed_copy, sizeof(seed_copy));

done:
    fflush(stdout);
    fkt_fuzz_quiet_end(saved_out);
    return 0;
}

static int fkt_fuzz_any_signed_inputs(void) {
    int i;
    for (i = 0; i < psbt_data.num_inputs; i++) {
        if (fkt_signer_signed_inputs[i])
            return 1;
    }
    return 0;
}

static int fkt_fuzz_try_sign_file(const char *path) {
    uint8_t seed_copy[64];
    int parsed;
    int rc;

    fkt_psbt_init();
    if (fkt_psbt_load_file(path) != 0)
        return -1;

    fkt_psbt_lenient_parse = 1;
    parsed = fkt_psbt_try_parse();
    fkt_psbt_lenient_parse = 0;
    if (parsed != 0)
        return -1;

    fkt_compute_hash_caches();
    fkt_signer_clear_signed_inputs();
    memcpy(seed_copy, FKT_FUZZ_SEED, 64);
    rc = fkt_sign_loaded_psbt(seed_copy, "", NULL, "/dev/null");
    fkt_memzero(seed_copy, sizeof(seed_copy));

    if (rc != 0)
        return -1;
    if (fkt_fuzz_any_signed_inputs())
        return 0;
    return -1;
}

int fkt_fuzz_regression_guard(void) {
    size_t i;
    int failures = 0;

    for (i = 0; i < sizeof(fkt_xfail_cases) / sizeof(fkt_xfail_cases[0]); i++) {
        char path[512];
        int rc;

        snprintf(path, sizeof(path), "%s/%s.psbt",
                 fkt_golden_unsigned_dir, fkt_xfail_cases[i]);
        rc = fkt_fuzz_try_sign_file(path);
        if (rc == 0) {
            fprintf(stderr, "REGRESSION: xfail case signed unexpectedly: %s\n",
                    fkt_xfail_cases[i]);
            failures++;
        }
    }

    if (failures != 0) {
        fprintf(stderr, "REGRESSION GUARD: %d / %lu xfail cases incorrectly signed\n",
                failures,
                (unsigned long)(sizeof(fkt_xfail_cases) / sizeof(fkt_xfail_cases[0])));
        return -1;
    }
    fprintf(stderr, "REGRESSION GUARD: %lu xfail cases must-reject OK\n",
            (unsigned long)(sizeof(fkt_xfail_cases) / sizeof(fkt_xfail_cases[0])));
    return 0;
}

#ifdef FKT_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fkt_fuzz_one_input(data, size);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    fkt_secp256k1_init();
    if (fkt_fuzz_regression_guard() != 0)
        abort();
    return 0;
}
#else

static int fkt_read_file_blob(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f;
    long sz;

    f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    sz = ftell(f);
    if (sz < 0 || (size_t)sz > FKT_FUZZ_MAX_INPUT) { fclose(f); return -1; }
    rewind(f);
    *out = (uint8_t *)malloc((size_t)sz);
    if (!*out) { fclose(f); return -1; }
    if (fread(*out, 1, (size_t)sz, f) != (size_t)sz) {
        free(*out);
        fclose(f);
        return -1;
    }
    fclose(f);
    *out_len = (size_t)sz;
    return 0;
}

static int fkt_read_stdin_blob(uint8_t **out, size_t *out_len) {
    size_t cap = 4096;
    size_t n = 0;
    uint8_t *buf = (uint8_t *)malloc(cap);
    int c;

    if (!buf) return -1;
    while ((c = getchar()) != EOF) {
        if (n >= cap) {
            cap *= 2;
            if (cap > FKT_FUZZ_MAX_INPUT) break;
            {
                uint8_t *nb = (uint8_t *)realloc(buf, cap);
                if (!nb) { free(buf); return -1; }
                buf = nb;
            }
        }
        buf[n++] = (uint8_t)c;
    }
    *out = buf;
    *out_len = n;
    return 0;
}

#define FKT_FUZZ_MAX_CORPUS 256

static int fkt_fuzz_collect_corpus(const char *dir, char paths[][1024], int max_n) {
    DIR *d;
    struct dirent *ent;
    int n = 0;

    d = opendir(dir);
    if (!d) return -1;

    while (n < max_n && (ent = readdir(d)) != NULL) {
        size_t name_len;
        if (ent->d_name[0] == '.')
            continue;
        name_len = strlen(ent->d_name);
        if (name_len + strlen(dir) + 2 > 1023)
            continue;
        snprintf(paths[n], 1024, "%s/%s", dir, ent->d_name);
        n++;
    }
    closedir(d);
    return n;
}

static int fkt_fuzz_run_corpus(const char *dir, int max_len, unsigned runs) {
    char paths[FKT_FUZZ_MAX_CORPUS][1024];
    int nfiles;
    unsigned count = 0;
    int i;

    nfiles = fkt_fuzz_collect_corpus(dir, paths, FKT_FUZZ_MAX_CORPUS);
    if (nfiles < 0) return -1;

    fkt_secp256k1_init();

    while (count < runs) {
        for (i = 0; i < nfiles && count < runs; i++) {
            uint8_t *blob;
            size_t len;

            if (fkt_read_file_blob(paths[i], &blob, &len) != 0)
                continue;
            if (len > (size_t)max_len) {
                free(blob);
                continue;
            }
            fkt_fuzz_one_input(blob, len);
            free(blob);
            count++;
        }
        if (nfiles == 0)
            break;
    }
    printf("Smoke fuzz: %u harness invocations (%d seeds, max_len=%d)\n",
           count, nfiles, max_len);
    return 0;
}

static int fkt_fuzz_parse_args(int argc, char **argv,
                               int *max_len, unsigned *runs,
                               const char **corpus, int *file_mode,
                               const char **single_file) {
    int i;

    *max_len = FKT_FUZZ_MAX_INPUT;
    *runs = 1;
    *corpus = NULL;
    *file_mode = 0;
    *single_file = NULL;

    for (i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-max_len=", 9) == 0) {
            *max_len = atoi(argv[i] + 9);
        } else if (strncmp(argv[i], "-runs=", 6) == 0) {
            *runs = (unsigned)atoi(argv[i] + 6);
            if (*runs == 0) *runs = 1;
        } else if (argv[i][0] != '-') {
            if (*corpus == NULL)
                *corpus = argv[i];
            else {
                *file_mode = 1;
                *single_file = argv[i];
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    int max_len;
    unsigned runs;
    const char *corpus;
    int file_mode;
    const char *single_file;
    uint8_t *blob;
    size_t len;

    fkt_fuzz_parse_args(argc, argv, &max_len, &runs, &corpus, &file_mode, &single_file);

    fkt_secp256k1_init();
    if (fkt_fuzz_regression_guard() != 0)
        return 2;

    if (corpus && !file_mode) {
        return fkt_fuzz_run_corpus(corpus, max_len, runs) != 0 ? 1 : 0;
    }

    if (single_file) {
        if (fkt_read_file_blob(single_file, &blob, &len) != 0)
            return 1;
        if (len > (size_t)max_len) len = (size_t)max_len;
        fkt_fuzz_one_input(blob, len);
        free(blob);
        return 0;
    }

    if (fkt_read_stdin_blob(&blob, &len) != 0)
        return 1;
    if (len > (size_t)max_len) len = (size_t)max_len;
    fkt_fuzz_one_input(blob, len);
    free(blob);
    return 0;
}
#endif