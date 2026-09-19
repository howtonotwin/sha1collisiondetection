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

/// API/ABI notes:
/// All exported symbols are prefixed either "sha1dc_" or "sha1_", and any such
/// identifiers should be considered reserved. All user-facing macros are
/// prefixed "SHA1DC_", and all such names are also reserved. When including a
/// library header, avoid having any macro definitions for all-lowercase
/// identifiers (even those that do not begin with one of the aforementioned
/// prefixes), except for those provided by the system.
///
/// Various possibly useful functions and constants beyond those in the
/// user-facing headers are exported (some optionally) from the library, at the
/// binary level, but nice headers for them have not been provided (yet).

// The type of SHA-1 expanded message blocks.
typedef uint32_t sha1_expanded_block[80];
// The type of SHA-1 hashes, the type of the input and output of the SHA-1
// compressor, and the type of the compressor's intermediate states.
typedef uint32_t sha1_chaining_value[5];
// A callback for handling collision blocks when they are found. The pointer
// arguments (except for `closure`) should be considered to become indeterminate
// upon return.
typedef void sha1dc_collision_handler(
  void *closure
, // Points past the end of the colliding blocks. In other words, the length of
  // the colliding prefix of the message stream. Could conceivably be greater
  // than the actual message size, in the event of a collision in the padding.
  uint64_t byte_offset
, // The actual suspicious message block (in the first 16 elements), expanded
  // (with 64 additional elements determined by the first 16).
  const sha1_expanded_block block_W
, // The message block that would be in the corresponding position of the
  // (otherwise unknown) "twin" message that collides with the (known) actual
  // message. (Also expanded.)
  const sha1_expanded_block twin_W
, // The actual chaining value (hash state) before the suspicious message block.
  const sha1_chaining_value block_in
, // The chaining value that the hash would need to be in before the twin block
  // in order to get the collision.
  const sha1_chaining_value twin_in);

// Overall state needed by the library to do SHA-1 hashing and collision
// detection for one message stream. The only public properties of the data type
// are the required alignment (compile-time constant; a stable part of the ABI)
// and the required size (a runtime constant).
struct sha1dc_ctx;

// Required alignment (in bytes) of `struct sha1dc_ctx`. On most systems, the
// required alignment is non-fundamental (not guaranteed by plain `malloc`).
constexpr size_t sha1dc_ctx_alignment = 64;
// Required size (in bytes) of `struct sha1dc_ctx`. Appropriate storage for a
// `struct sha1dc_ctx` is then provided by, e.g.,
//
//     alignas(sha1dc_ctx_alignment) char storage[sha1dc_ctx_size()];
//     struct sha1dc_ctx *ctx = (void*)storage;
size_t sha1dc_ctx_size [[gnu::const]]() [[unsequenced]];

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
// "Safe SHA-1" avoids SHA-1 collisions when they are detected by hashing the
// offending message block 2 extra times. Thus, even though "safe SHA-1" should
// be compatible with SHA-1 for all legitimate users, for attackers "safe SHA-1"
// has about the same cryptographic strength as if SHA-1 were extended from 80
// steps to 240 steps. The best collision attacks against SHA-1 have a
// complexity of ~2^60 hash evaluations, so for 240 steps an immediate
// lower-bound for the best cryptanalytic attacks would be 2^180. An attacker
// would be better off using a generic birthday search of complexity 2^80.
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
  unsigned char[static sizeof(sha1_chaining_value)]
, struct sha1dc_ctx *restrict);

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
  // A prescribed pattern of message block bit flips. An attacker "must" use
  // (unless they have a fundamentally novel attack or an implausibly powerful
  // computer) the mask of an "easy" DV to construct a collision attack.
  uint32_t      message_mask[80];
};
// The attack classes defended against. These are expected to be the "easiest"
// DVs for an attacker to follow to an attack, so they are expected to be the
// most important to defend against. The size of this list represents a somewhat
// arbitrary difficulty cutoff (chosen for computational efficiency); DVs beyond
// these ones are deemed so unlikely to be used they are not worth testing for.
//
// This is essentially a high-level summary of the capabilities of the library.
// It may be expanded or otherwise changed in different versions of the library.
extern const struct sha1dc_disturbance_vector sha1dc_disturbance_vectors[];
// The number of elements of `sha1dc_disturbance_vectors`.
extern const size_t sha1dc_n_disturbance_vectors;
