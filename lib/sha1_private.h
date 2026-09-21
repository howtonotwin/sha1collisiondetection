// © 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
// © 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>
// SPDX-License-Identifier: MIT
//
// License text available in accompanying file LICENSE.txt, or at
// https://opensource.org/licenses/MIT.
#pragma once
#include "private.h"
#include "data.h"

#include "sha1.h"

struct sha1dc_ctx {
  // Hash state proper
  uint32_t buffer[16];    // storage for incomplete blocks
  sha1_chaining_value cv; // chaining value (running hash)
  uint64_t bytes;         // total bytes buffered or added to cv

  // Library settings
  bool found_collision    : 1;
  bool do_safe_hash       : 1;
  bool detect_coll        : 1;
  bool ubc_check          : 1;
  bool reduced_round_coll : 1;

  sha1dc_collision_handler *collision;
  void *collision_closure;

  // Scratch space for sha1dc_process, so it doesn't need to allocate a highly
  // aligned data block on every call (i.e. every 512 input bits!).
  // ("Allocation" includes putting this data on the stack, as even that is too
  // expensive for such hot code).
  sha1_chaining_value block_in, twin_in, twin_out; // "block_out" would be cv
  sha1_expanded_block block_W,  twin_W;
  sha1_chaining_value block_state[sha1dc_n_needed_states_defn];
};
static_assert(alignof(struct sha1dc_ctx) <= sha1dc_ctx_alignment);

extern typeof(sha1dc_disturbance_vectors_defn) sha1dc_disturbance_vectors;

DECLARE_PROTECTED(ctx_size);
extern DECLARE_PROTECTED(disturbance_vectors);
extern DECLARE_PROTECTED(n_disturbance_vectors);
