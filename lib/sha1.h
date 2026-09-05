/***
* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
* Distributed under the MIT Software License.
* See accompanying file LICENSE.txt or copy at
* https://opensource.org/licenses/MIT
***/

#ifndef SHA1DC_SHA1_H
#define SHA1DC_SHA1_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <stdint.h>
#include <limits.h>

static_assert(CHAR_BIT == 8);

// The type of SHA-1 expannded message blocks.
typedef uint32_t sha1_expanded_block_t[80];
// The type of SHA-1 hashes, the type of the input and output of the SHA-1
// compressor, and the type of the compressor's intermediate states.
typedef uint32_t sha1_chaining_value_t[5];
// A callback for handling collision blocks when they are found.
typedef void sha1dc_collision_handler_t(
  void *closure, uint64_t byte_offset
, const sha1_chaining_value_t in_1, const sha1_chaining_value_t in_2
, const sha1_expanded_block_t mb_1, const sha1_expanded_block_t mb_2);

// Various "plain SHA1" functions may be optionally exported, but we do not
// declare them here.

// Overall state needed by the library to do SHA-1 hashing and collision
// detection for one message stream.
struct sha1dc_ctx {
	uint64_t bytes;
	uint32_t ihv[5];
	uint32_t buffer[16];
	bool found_collision    : 1;
	bool safe_hash          : 1;
	bool detect_coll        : 1;
	bool ubc_check          : 1;
	bool reduced_round_coll : 1;

  sha1dc_collision_handler_t *collision;
  void *collision_closure;

	sha1_chaining_value_t ihv1, ihv2;
  sha1_expanded_block_t m1, m2;
  sha1_chaining_value_t states[80];
};

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
  struct sha1dc_ctx*, sha1dc_collision_handler_t*, void*);

// Add some message data to the hash.
void sha1dc_ingest(
  struct sha1dc_ctx *restrict
, const unsigned char*, size_t n);

// Terminate a hash computation and get a 160-bit hash value. This involves
// computing the appropriate padding and feeding it to the hash, so the state
// needs to be reinitialized if it is to be reused.
//
// Returns whether a collision was detected.
bool sha1dc_finish(
  unsigned char[static restrict 20], struct sha1dc_ctx *restrict);

#if defined(__cplusplus)
}
#endif

#endif
