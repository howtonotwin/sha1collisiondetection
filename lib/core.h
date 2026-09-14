#pragma once
#include <stdckdint.h>
#include <string.h>

#include "bits.h"
#include "sha1.h"

// Accumulate a raw message block into the context, handling a collision if one
// is found. `ctx->bytes` needs to have been updated beforehand.
void sha1dc_process(
  struct sha1dc_ctx      *restrict ctx
, const uint32_t UNALIGN block[static restrict 16]);
// NB: `ctx->buffer` is not modified by this function, so it *is* allowed to
//     pass `ctx->buffer` for `block`.

// The size in `uint8_t`s of a bitmask capable of representing a subset of the
// `sha1dc_disturbance_vectors`. The bits of the mask correspond to the array
// elements in little-endian order (`mask[0] & 1` is associated to
// `sha1dc_disturbance_vectors[0]`, etc.).
#define SHA1DC_DECLARE_DVMASK_BYTES(dvmask_bytes) \
  size_t dvmask_bytes [[gnu::const]]() [[unsequenced]]
#define SHA1DC_DEFINE_DVMASK_BYTES(dvmask_bytes, n_disturbance_vectors) \
  SHA1DC_DECLARE_DVMASK_BYTES(dvmask_bytes) { \
    return n_disturbance_vectors + 7 >> 3;    \
  }
#if SHA1DC_INSIDE_LIBRARY
SHA1DC_DECLARE_DVMASK_BYTES(sha1dc_dvmask_bytes);
#else
inline SHA1DC_DEFINE_DVMASK_BYTES(
  sha1dc_dvmask_bytes, sha1dc_n_disturbance_vectors)
#endif

// Are any DVs specified in the mask?
#define SHA1DC_DECLARE_CHECK_DVMASK(check_dvmask, dvmask_bytes) \
  bool check_dvmask(                                           \
    const uint8_t mask[static dvmask_bytes()]) [[unsequenced]]
#define SHA1DC_DEFINE_CHECK_DVMASK(check_dvmask, dvmask_bytes) \
  SHA1DC_DECLARE_CHECK_DVMASK(check_dvmask, dvmask_bytes) {   \
    uint32_t buf;                                             \
    size_t i = 0, after;                                      \
    while(!ckd_sub(&after, dvmask_bytes() - i, sizeof buf)) { \
      memcpy(&buf, mask + i, sizeof buf);                     \
      if(buf) return true;                                    \
      i += sizeof buf;                                        \
    }                                                         \
    buf = 0;                                                  \
    memcpy(&buf, mask + i, after + sizeof buf);               \
    return buf;                                               \
  }
#if SHA1DC_INSIDE_LIBRARY
SHA1DC_DECLARE_CHECK_DVMASK(sha1dc_check_dvmask, sha1dc_dvmask_bytes);
#else
inline SHA1DC_DEFINE_CHECK_DVMASK(sha1dc_check_dvmask, sha1dc_dvmask_bytes)
#endif

// Given an expanded SHA-1 message block, test it for signs of having been
// constructed according to one of the `sha1dc_disturbance_vectors`, and return
// a dvmask containing a set bit for each DV that could not be ruled out. (The
// message should then be checked more closely for those DVs.)
//
// On random (non-malicious) data, the false positive rate is about 4.7%.
void sha1dc_ubc_check [[gnu::access(write_only, 2)]](
  uint32_t const expanded_message[static restrict 80]
, uint8_t        dvmask[static restrict sha1dc_dvmask_bytes()]) [[unsequenced]];
