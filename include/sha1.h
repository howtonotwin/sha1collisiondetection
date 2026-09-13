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

#if CHAR_BIT != 8
#warning "bytes are not 8 bits on this platform; expect breakage!"
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
// Required size of `struct sha1dc_ctx`, including an appropriately sized
// `states` array.
extern const size_t sha1dc_ctx_size;
// =   sizeof(struct sha1dc_ctx)
//   + sizeof(sha1_chaining_value) * sha1dc_n_needed_states;

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
extern const size_t sha1dc_dvmask_bytes;
// = sha1dc_n_disturbance_vectors + 7 >> 3;

// Are any DVs specified in the mask? (This is a convenience/optimization; one
// may directly check the first `sha1dc_n_disturbance_vectors` bits of
// `dvmask`.)
bool sha1dc_check_dvmask(
  const uint8_t dvmask[static sha1dc_dvmask_bytes]) [[unsequenced]];

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

// Set whether the computed hash is really SHA-1 (when `false`) or if it's a
// slightly modified version, "safe SHA-1", that is not susceptible to the same
// collision attacks (used when `true`). The key property of "safe SHA-1" is
// that it has the same value as SHA-1 on almost all inputs, except on those
// inputs that are detected to be malicious. The chance of a non-malicious input
// block being mistaken for malicious is ~2^-90.
//
// "Safe SHA-1" is intended to be a drop-in replacement for applications that
// used SHA-1 and need to maintain backwards compatibility. When "safe SHA-1" is
// used, it is not necessary for application logic to explicitly handle the case
// of a SHA-1 collision attack being detected.
//
// "Safe SHA-1" avoid SHA-1 collisions when they are detected by hashing the
// offending message block 3 times. Thus, even though "safe SHA-1" should be
// compatible with SHA-1 for all legitimate users, for attackers "safe SHA-1"
// has the same cryptographic strength as if SHA-1 were extended from 80 steps
// to 240 steps. The best collision attacks against SHA-1 have complexity about
// 2^60, so for 240 steps an immediate lower-bound for the best cryptanalytic
// attacks would be 2^180. An attacker would be better off using a generic
// birthday search of complexity 2^80.
//
// Enabled by default. (That is, the default is to use "safe SHA-1".) The
// default can also be changed at compile time by setting
// `SHA1DC_INIT_SAFE_HASH_DEFAULT` to 0. Even when "safe SHA-1" is enabled,
// there is no effect unless `sha1dc_set_detect_coll` is also enabled.
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
void sha1dc_ingest(
  size_t n;
  struct sha1dc_ctx *restrict
, const unsigned char[static n], size_t n);

// Terminate a hash computation and get a 160-bit hash value. This involves
// computing the appropriate padding and feeding it to the hash, so the state
// needs to be reinitialized if it is to be reused.
//
// Returns whether a collision was detected.
bool sha1dc_finish [[gnu::access(write_only, 1)]](
  unsigned char[static 20]
, struct sha1dc_ctx *restrict);
