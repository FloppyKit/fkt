#include "fkt_psbt.h"
#include "fkt_sha256.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>           

/* Uncomment the line below to enable debug prints */
/* #define FKT_DEBUG */

/* #### SECTION: Static PSBT buffer & cursor #### */

uint8_t  psbt_buffer[FKT_PSBT_MAX_SIZE];
size_t   psbt_size;
static const uint8_t *psbt_cursor;
static const uint8_t *psbt_end;

#define MAX_PSBT_ITEMS  256



/* #### SECTION: Parsed PSBT data (all extracted info) #### */
fkt_psbt_state psbt_data;

/* #### SECTION: Signing hash caches & separator offsets #### */
uint8_t hashPrevouts[32];
uint8_t hashSequence[32];
uint8_t sha_prevouts[32];
uint8_t sha_amounts[32];
uint8_t sha_scriptpubkeys[32];
uint8_t sha_sequences[32];
uint8_t sha_outputs[32];
uint8_t hashOutputs[32];

size_t input_separator_offsets[MAX_PSBT_ITEMS];
size_t input_map_start_offsets[MAX_PSBT_ITEMS];
int    input_separator_count;
size_t output_separator_offsets[MAX_PSBT_ITEMS];
size_t output_map_start_offsets[MAX_PSBT_ITEMS];
int    output_separator_count;

/* #### SECTION: Error handler #### */
static void fkt_psbt_die(const char *msg) {
    fprintf(stderr, "FKT PSBT ERROR: %s\n", msg);
    exit(1);
}
/* #### SECTION: fkt_psbt_init (zero all state) #### */
void fkt_psbt_init(void) {
    volatile uint8_t *p; size_t i;
    p = (volatile uint8_t*)psbt_buffer;
    for(i=0;i<sizeof(psbt_buffer);i++) p[i]=0;
    p = (volatile uint8_t*)&psbt_data;
    for(i=0;i<sizeof(psbt_data);i++) p[i]=0;
    psbt_size = 0; psbt_cursor = NULL; psbt_end = NULL;
    input_separator_count = 0;
    output_separator_count = 0;
    memset(input_separator_offsets, 0, sizeof(input_separator_offsets));
    memset(input_map_start_offsets, 0, sizeof(input_map_start_offsets));
    memset(output_separator_offsets, 0, sizeof(output_separator_offsets));
    memset(output_map_start_offsets, 0, sizeof(output_map_start_offsets));
}

/* PLACEHOLDER_TRUNCATED_FOR_SIZE */