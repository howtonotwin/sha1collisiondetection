#pragma once
#include "sha1.h"

// Accumulate a raw message block into the context, not even bumping 
void sha1dc_process [[gnu::visibility("protected")]](
  struct sha1dc_ctx *restrict ctx
, const uint32_t    block[static restrict 16]);
// NB: it *is* allowed to pass `ctx->buffer` for `block`, because neither `*ctx`
// nor `ctx->buffer` nor any element of `ctx->buffer` are accessed.

// Given an expanded SHA-1 message block, test it for signs of having been
// constructed according to one of the `sha1dc_disturbance_vectors`, and return
// a dvmask containing a set bit for each DV that could not be ruled out. (The
// message should then be checked more closely for those DVs.)
//
// On random (non-malicious) data, the false positive rate is about 4.7%.
void sha1dc_ubc_check
[[gnu::visibility("protected"), gnu::access(write_only, 2)]](
  uint32_t const expanded_message[static restrict 80]
, uint8_t        dvmask[static restrict sha1dc_dvmask_bytes()]) [[unsequenced]];
