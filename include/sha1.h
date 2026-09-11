#pragma once
/***
* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
* Distributed under the MIT Software License.
* See accompanying file LICENSE.txt or copy at
* https://opensource.org/licenses/MIT
***/

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#if defined __GNUC__ && !defined __clang__
# define SHA1DC_FWDPRM_EXTENSION __extension__
# define SHA1DC_FORWARD_PARAM(p) p;
# define SHA1DC_FORWARDED(p)     p
#else
# define SHA1DC_FWDPRM_EXTENSION
# define SHA1DC_FORWARD_PARAM(p)
# define SHA1DC_FORWARDED(p)
#endif

#if CHAR_BIT != 8
#error "bytes are not 8 bits on this platform; expect breakage!"
#endif

// The type of SHA-1 expanded message blocks.
typedef uint32_t sha1_expanded_block[80];
// The type of SHA-1 hashes, the type of the input and output of the SHA-1
// compressor, and the type of the compressor's intermediate states.
typedef uint32_t sha1_chaining_value[5];
// A callback for handling collision blocks when they are found.
typedef void sha1dc_collision_handler(
  void *closure, uint64_t byte_offset
, const sha1_chaining_value in_1, const sha1_chaining_value in_2
, const sha1_expanded_block mb_1, const sha1_expanded_block mb_2);

// Various "plain SHA1" functions may be optionally exported, but we do not
// declare them here.

// Overall state needed by the library to do SHA-1 hashing and collision
// detection for one message stream.
struct sha1dc_ctx {
  alignas(64) uint32_t buffer[16];
  uint32_t ihv[5];
  uint64_t bytes;
  bool found_collision    : 1;
  bool safe_hash          : 1;
  bool detect_coll        : 1;
  bool ubc_check          : 1;
  bool reduced_round_coll : 1;

  sha1dc_collision_handler *collision;
  void *collision_closure;

  sha1_chaining_value ihv1, ihv2;
  sha1_expanded_block m1, m2;
  sha1_chaining_value states[];
};
// Number of states that there must be space for in `struct sha1dc_ctx::states`.
extern const size_t sha1dc_n_needed_states;
inline size_t sha1dc_ctx_size() [[unsequenced]] {
  return sizeof(struct sha1dc_ctx)
       + sizeof(sha1_chaining_value) * sha1dc_n_needed_states;
}

// Description of a class of attacks against SHA-1.
struct sha1dc_disturbance_vector {
  // The class, k, and b define the DV. The classification is due to Manuel.
  enum sha1dc_disturbance_vector_class : unsigned char {
    sha1dc_disturbance_vector_class_I = 1,
    sha1dc_disturbance_vector_class_II
  }             class;
  unsigned char k, b;
  // A particular point in the compressor (measured in words consumed), where
  // the compressor state as a message block is being processed should be saved
  // in order to be able to definitively check it for signs of being constructed
  // as prescribed by this DV.
  unsigned char test_state;
  uint32_t      message_mask[80];
};
// "Easiest" known attack classes
extern const struct sha1dc_disturbance_vector sha1dc_disturbance_vectors[];
// The number of attack classes defended against. The difficulty cutoff thus
// represented is somewhat arbitrary. This is also the number of elements of
// `sha1dc_disturbance_vectors`.
extern const size_t sha1dc_n_disturbance_vectors;

// The size in `uint8_t`s of a bitmask capable of representing a subset of the
// `sha1dc_disturbance_vectors`. The bits of the mask correspond to the array
// elements in little-endian order (`mask[0] & 1` is associated to
// `sha1dc_disturbance_vectors[0]`, etc.).
inline size_t sha1dc_dvmask_bytes() [[unsequenced]] {
  return sha1dc_n_disturbance_vectors + 7 >> 3;
}
// Are any DVs specified in the mask? (This is a convenience/optimization; one
// may directly check the first `sha1dc_n_disturbance_vectors` bits of
// `dvmask`.)
bool sha1dc_check_dvmask(
  const uint8_t dvmask[static restrict sha1dc_dvmask_bytes()]) [[unsequenced]];
// Would be inline (the definition is "public"), but then compilers prefer
// inlining the function to calling it, when the opposite is better.

// Summary of the `test_state`s of all the `sha1dc_disturbance_vectors`. States
// (numbered 0 to 80, inclusive) have a nonnegative entry here if any DV needs
// them, and they have a -1 if they are never needed.
//
// The nonnegative number for states that are needed is the number of that state
// among the needed states. I.e. it is the index for that state into an array of
// states where the unneeded states do not get array elements.
extern const signed char sha1dc_need_state[81];

// Initialize the context with the default library settings and the hash
// function state that is appropriate for processing a new message from its
// beginning.
void sha1dc_init(struct sha1dc_ctx*);

// Set whether SHA-1 collisions should be handled silently, without an error.
// This modifies the hash function, so it is no longer SHA-1, but instead a new
// function, "safe SHA-1". One key property of "safe SHA-1" is that it has the
// same value as SHA-1 on almost all inputs, except on those inputs that it
// detects as malicious. The chance of a non-malicious input block being
// mistaken for malicious is ~2^-90.
//
// The other key property of "safe SHA-1" is that it's harder for attackers to
// find collisions in. When a SHA-1 collision is detected, the near-collision
// block is hashed 3 times. Effectively, SHA-1 is extended from 80 steps to 240
// steps for such blocks. The best collision attacks against SHA-1 have
// complexity about 2^60, so for 240 steps an immediate lower-bound for the best
// cryptanalytic attacks would be 2^180. An attacker would be better off using a
// generic birthday search of complexity 2^80.
//
// Enabled by default. The default can also be changed at compile time by
// setting `SHA1DC_INIT_SAFE_HASH_DEFAULT`. Even if set, there is no effect
// unless `sha1dc_set_detect_coll` is also enabled.
void sha1dc_set_safe(struct sha1dc_ctx*, bool);

// Set whether "unavoidable bit conditions" should be used to reduce the amount
// of work done. This provides a large speedup. Enabled by default.
void sha1dc_set_use_ubc(struct sha1dc_ctx*, bool);

// Set whether collisions should be detected at all. Enabled by default.
void sha1dc_set_detect_coll(struct sha1dc_ctx*, bool);

// Set whether collisions against a modified SHA-1 with fewer rounds should also
// be detected. It is easier to construct collisions for such a reduced
// function, so this option is useful for testing. Disabled by default.
void sha1dc_set_detect_reduced_round_coll(struct sha1dc_ctx*, bool);

// Set a handler for detected collisions, or `nullptr` to not call any handler.
// Set to `nullptr` by default.
void sha1dc_set_callback(
  struct sha1dc_ctx*, sha1dc_collision_handler*, void*);

// Add some message data to the hash.
SHA1DC_FWDPRM_EXTENSION void sha1dc_ingest(
  SHA1DC_FORWARD_PARAM(size_t n)
  struct sha1dc_ctx *restrict
, const unsigned char[SHA1DC_FORWARDED(static n)], size_t n);

// Terminate a hash computation and get a 160-bit hash value. This involves
// computing the appropriate padding and feeding it to the hash, so the state
// needs to be reinitialized if it is to be reused.
//
// Returns whether a collision was detected.
bool sha1dc_finish [[gnu::access(write_only, 1)]](
  unsigned char[static 20]
, struct sha1dc_ctx *restrict);

#ifndef SHA1DC_KEEP_DEFINES
#undef SHA1DC_FWDPRM_EXTENSION
#undef SHA1DC_FORWARD_PARAM
#undef SHA1DC_FORWARDED
#endif
