/* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
* Distributed under the MIT Software License.
* See accompanying file LICENSE.txt or copy at
* https://opensource.org/licenses/MIT
***/
#ifndef SHA1DC_UBC_CHECK_H
#define SHA1DC_UBC_CHECK_H

#ifdef __cplusplus
#warning "sha1dc/ubc_check.h is not compatible with C++"
#endif

#include <stddef.h>

// Description of a class of attacks against SHA-1.
struct sha1dc_disturbance_vector {
  enum sha1dc_disturbance_vector_class : unsigned char {
    sha1dc_disturbance_vector_class_I = 1,
    sha1dc_disturbance_vector_class_II
  }             class;
  unsigned char k, b, test_t;
  uint32_t      message_mask[80];
};
// "Easiest" known attack classes
extern const struct sha1dc_disturbance_vector
sha1dc_disturbance_vectors [[gnu::visibility("protected")]][];
// The number of attack classes defended against. The difficulty cutoff thus
// represented is somewhat arbitrary. This is also the number of elements of
// `sha1dc_disturbance_vectors`.
extern const size_t
sha1dc_n_disturbance_vectors [[gnu::visibility("protected")]];

// The size in uint8_ts of the mask that ubc_check returns, representing a set
// of DVs that might have been used to construct a given input. The bits of the
// dvmask correspond to the `sha1dc_disturbance_vectors`, in little-endian order
// (`mask[0] & 1` is associated to `sha1dc_disturbance_vectors[0]`, etc.).
inline size_t sha1dc_dvmask_bytes [[gnu::visibility("protected")]]()
[[unsequenced]] {
  return sha1dc_n_disturbance_vectors + 7 >> 3;
}
// Are any DVs specified in the mask? (This is a convenience/optimization; one
// may directly check the first `sha1dc_n_disturbance_vectors` bits of `dvmask`.)
bool sha1dc_check_dvmask [[gnu::visibility("protected")]](
  const uint8_t dvmask[static restrict sha1dc_dvmask_bytes()]) [[unsequenced]];
// Would be inline (the definition is "public"), but then compilers prefer
// inlining the function to calling it, when the opposite is better.

extern const size_t
sha1dc_n_needed_states [[gnu::visibility("protected")]];
// States marked with -1 are not needed. States marked with a nonnegative number
// are needed, and that nonnegative number is the number of that state among the
// needed states (i.e. the index for that state into an array of states where
// the unneeded states do not get array elements).
extern const signed char
sha1dc_need_state [[gnu::visibility("protected")]][81];

// Given an expanded SHA-1 message block, test it for signs of having been
// constructed according to one of the `sha1dc_disturbance_vectors`, and return
// a dvmask containing a set bit for each DV that could not be ruled out. (The
// message should then be checked more closely for those DVs.)
//
// On random (non-malicious) data, the false positive rate is about 4.7%.
void sha1dc_ubc_check [[gnu::access(write_only, 2)]](
  uint32_t const expanded_message[static restrict 80]
, uint8_t        dvmask[static restrict sha1dc_dvmask_bytes()]) [[unsequenced]];

#endif
