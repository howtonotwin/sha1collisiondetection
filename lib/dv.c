// © 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>
// SPDX-License-Identifier: MIT
//
// License text available in accompanying file LICENSE.txt, or at
// https://opensource.org/licenses/MIT.
#include <stdcountof.h>
#include <stddef.h>
#include <stdlib.h>

#include "util.h"
#include "data.h"

#include "sha1_private.h"
#include "core_private.h"

// This "extern [[gnu::alias(constexpr-static)]]" business is super janky and
// quite possibly not intended to work, but it works.
extern typeof(PROTECTED(disturbance_vectors)) PROTECTED(disturbance_vectors) [[
  gnu::alias("sha1dc_disturbance_vectors_defn")]];
const size_t PROTECTED(n_disturbance_vectors) =
  countof PROTECTED(disturbance_vectors);
extern EXPORT_PROTECTED(disturbance_vectors);
extern EXPORT_PROTECTED(n_disturbance_vectors);

extern typeof(sha1dc_need_state) sha1dc_need_state [[
  gnu::alias("sha1dc_need_state_defn")]];
extern const size_t sha1dc_n_needed_states [[
  gnu::alias("sha1dc_n_needed_states_defn")]];

extern SHA1DC_DEFINE_DVMASK_BYTES(
  PROTECTED(dvmask_bytes), PROTECTED(n_disturbance_vectors))
SHA1DC_DEFINE_CHECK_DVMASK(
  PROTECTED(check_dvmask), PROTECTED(dvmask_bytes)
, SMALL_STATIC_FOR)
EXPORT_PROTECTED(dvmask_bytes);
EXPORT_PROTECTED(check_dvmask);

size_t PROTECTED(ctx_size)() {
  return sizeof(struct sha1dc_ctx);
}
EXPORT_PROTECTED(ctx_size);
