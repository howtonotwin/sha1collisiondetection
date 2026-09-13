#pragma once
#include "bits.h"
#include "sha1.h"

// The size in `uint8_t`s of a bitmask capable of representing a subset of the
// `sha1dc_disturbance_vectors`. The bits of the mask correspond to the array
// elements in little-endian order (`mask[0] & 1` is associated to
// `sha1dc_disturbance_vectors[0]`, etc.).
extern const size_t sha1dc_dvmask_bytes;
// = sha1dc_n_disturbance_vectors + 7 >> 3;

// Are any DVs specified in the mask?
//
// This is a convenience/optimization; one may directly check the first
// `sha1dc_n_disturbance_vectors` bits of `dvmask`. (Actually, if/while this is
// library internal, LTO will take care of the optimization part. But it would
// be useful for library consumers if it were exposed.)
bool sha1dc_check_dvmask(
  const uint8_t dvmask[static sha1dc_dvmask_bytes]) [[unsequenced]];

// Accumulate a raw message block into the context.
void sha1dc_process(
  struct sha1dc_ctx *restrict ctx
, const uint32_t UNALIGN block[static restrict 16]);
// NB: `ctx->buffer` is not modified by this function, so it *is* allowed to
//     pass `ctx->buffer` for `block`.

// Given an expanded SHA-1 message block, test it for signs of having been
// constructed according to one of the `sha1dc_disturbance_vectors`, and return
// a dvmask containing a set bit for each DV that could not be ruled out. (The
// message should then be checked more closely for those DVs.)
//
// On random (non-malicious) data, the false positive rate is about 4.7%.
void sha1dc_ubc_check [[gnu::access(write_only, 2)]](
  uint32_t const expanded_message[static restrict 80]
, uint8_t        dvmask[static restrict sha1dc_dvmask_bytes]) [[unsequenced]];
