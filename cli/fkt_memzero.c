/* fkt_memzero.c – volatile secure zeroing + SIGINT wipe */
#define _POSIX_C_SOURCE 200809L
#include "fkt_memzero.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile uint8_t *g_seed;
static size_t g_seed_len;
static volatile char *g_mnemonic;
static size_t g_mnemonic_len;
static volatile void *g_words;
static size_t g_words_len;
static volatile void *g_b64;
static size_t g_b64_len;

void fkt_memzero(volatile void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--)
        *p++ = 0;
}

void fkt_memzero_register_seed(volatile uint8_t *seed, size_t len) {
    g_seed = seed;
    g_seed_len = len;
}

void fkt_memzero_register_mnemonic(volatile char *mnemonic, size_t len) {
    g_mnemonic = mnemonic;
    g_mnemonic_len = len;
}

void fkt_memzero_register_words(volatile void *words, size_t len) {
    g_words = words;
    g_words_len = len;
}

void fkt_memzero_register_b64(volatile void *buf, size_t len) {
    g_b64 = buf;
    g_b64_len = len;
}

void fkt_memzero_wipe_all(void) {
    if (g_seed && g_seed_len)
        fkt_memzero(g_seed, g_seed_len);
    if (g_mnemonic && g_mnemonic_len)
        fkt_memzero(g_mnemonic, g_mnemonic_len);
    if (g_words && g_words_len)
        fkt_memzero(g_words, g_words_len);
    if (g_b64 && g_b64_len)
        fkt_memzero(g_b64, g_b64_len);
    g_seed = NULL;
    g_seed_len = 0;
    g_mnemonic = NULL;
    g_mnemonic_len = 0;
    g_words = NULL;
    g_words_len = 0;
    g_b64 = NULL;
    g_b64_len = 0;
}

static void fkt_sigint_handler(int sig) {
    (void)sig;
    fkt_memzero_wipe_all();
    fprintf(stderr, "\nSIGINT — zeroed all key material.\n");
    _exit(130);
}

void fkt_memzero_install_sigint(void) {
    struct sigaction sa;
    sa.sa_handler = fkt_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
}