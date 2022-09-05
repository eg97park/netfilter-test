//
// from : suricata-4.1.8.tar.gz > src > util_spm_bm.h
// modified by gilgil
//

#pragma once

#include <stdint.h>

#define ALPHABET_SIZE 256

/* Context for booyer moore */
typedef struct BmCtx_ {
	uint16_t bmBc[ALPHABET_SIZE];
	uint16_t *bmGs; // = SCMalloc(sizeof(int32_t)*(needlelen + 1));
} BmCtx;

BmCtx *BoyerMooreCtxInit(const uint8_t *needle, uint16_t needle_len);
uint8_t *BoyerMoore(const uint8_t *x, uint16_t m, const uint8_t *y, uint32_t n, BmCtx *bm_ctx);
void BoyerMooreCtxDeInit(BmCtx *);

