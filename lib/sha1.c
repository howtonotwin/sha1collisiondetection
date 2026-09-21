// © 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
// © 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>
// SPDX-License-Identifier: MIT
//
// License text available in accompanying file LICENSE.txt, or at
// https://opensource.org/licenses/MIT.
#include <limits.h>
#include <stdbit.h>
#include <stdcountof.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "util.h"
#include "x86.h"

#include "bits.h"
#include "core_private.h"
#include "sha1_private.h"

static inline uint32_t sha1_expand_one(const uint32_t *W) {
  return sha1_rotate_left(W[-3] ^ W[-8] ^ W[-14] ^ W[-16], 1);
}

#define sha1_A(cv) 0[cv]
#define sha1_B(cv) 1[cv]
#define sha1_C(cv) 2[cv]
#define sha1_D(cv) 3[cv]
#define sha1_E(cv) 4[cv]
static inline uint32_t sha1_fIF(uint32_t b, uint32_t c, uint32_t d) {
  return b & (c ^ d) ^ d;
}
static inline uint32_t sha1_fXOR(uint32_t b, uint32_t c, uint32_t d) {
  return b ^ c ^ d;
}
static inline uint32_t sha1_fMAJ(uint32_t b, uint32_t c, uint32_t d) {
  return b & c | d & (b ^ c);
}
static inline uint32_t sha1_fk(
  uint32_t b, uint32_t c, uint32_t d, unsigned char t) {
  switch(t / 20) {
  case 0:
    return  sha1_fIF(b, c, d) + 0x5A827999;
  case 1:
    return sha1_fXOR(b, c, d) + 0x6ED9EBA1;
  case 2:
    return sha1_fMAJ(b, c, d) + 0x8F1BBCDC;
  case 3:
    return sha1_fXOR(b, c, d) + 0xCA62C1D6;
  default:
    unreachable();
  }
}

// t is the current step number
static inline void sha1_step(
  uint32_t cv[static 5], uint32_t m, unsigned char t) {
  uint32_t q = sha1_E(cv);
  q += sha1_rotate_left(sha1_A(cv), 5);
  q += sha1_fk(sha1_B(cv), sha1_C(cv), sha1_D(cv), t);
  q += m;
  sha1_E(cv) = sha1_D(cv);
  sha1_D(cv) = sha1_C(cv);
  sha1_C(cv) = sha1_rotate_right(sha1_B(cv), 2);
  sha1_B(cv) = sha1_A(cv);
  sha1_A(cv) = q;
}
// t is the *target* step number
static inline void sha1_step_bw(
  uint32_t cv[static 5], uint32_t m, unsigned char t) {
  uint32_t q = sha1_A(cv);
  sha1_A(cv) = sha1_B(cv);
  sha1_B(cv) = sha1_rotate_left(sha1_C(cv), 2);
  sha1_C(cv) = sha1_D(cv);
  sha1_D(cv) = sha1_E(cv);
  q -= m;
  q -= sha1_fk(sha1_B(cv), sha1_C(cv), sha1_D(cv), t);
  q -= sha1_rotate_left(sha1_A(cv), 5);
  sha1_E(cv) = q;
}

// SHA-1's compression function (including the feed-forward), which takes an
// expanded message block.
static void sha1_add_block(
  uint32_t       cv[static restrict  5]
, const uint32_t  W[static restrict 80]) {
  sha1_chaining_value state;
  memcpy(state, cv, sizeof state);

  STATIC_FOR(unsigned char i = 0; i < 80; i++) sha1_step(state, W[i], i);

  for(size_t i = 0; i < countof state; i++) cv[i] += state[i];
}

// SHA-1's update function, including the message read-in (i.e. endianness
// handling) and expansion. It's not actually used (yet), but it's kept around
// as a reference for plain SHA1.
static void sha1_add_block_expanding [[maybe_unused]](
  uint32_t               cv[static restrict  5]
, const uint32_t UNALIGN  m[static restrict 16]) {
  sha1_expanded_block W;
  sha1_chaining_value state;
  memcpy(state, cv, sizeof state);

  STATIC_FOR(unsigned char i = 0; i < 80; i++) {
    W[i] =
        i < 16
      ? sha1_load8_maybe_unaligned_beu32((const unsigned char*)(m + i))
      : sha1_expand_one(W + i);
    sha1_step(state, W[i], i);
  }

  for(size_t i = 0; i < countof state; i++) cv[i] += state[i];
}

// The same as sha1_add_block_expanding, but saving W and some states.
static void sha1_add_block_expanding_saving_portable(
  uint32_t                   cv[static restrict  5]
, const uint32_t UNALIGN      m[static restrict 16]
, uint32_t                    W[static restrict 80]
, sha1_chaining_value    states[static restrict sha1dc_n_needed_states]) {
  sha1_chaining_value state;
  memcpy(state, cv, sizeof state);
  size_t saved = 0;

  STATIC_FOR(unsigned char i = 0; true; i++) {
    if(signed char slot = sha1dc_need_state[i]; slot != -1) {
      if((unsigned)slot != saved) unreachable();
      memcpy(states[saved++], state, sizeof state);
    }
    if(i >= 80) break;

    W[i] =
        i < 16
      ? sha1_load8_maybe_unaligned_beu32((const unsigned char*)(m + i))
      : sha1_expand_one(W + i);
    sha1_step(state, W[i], i);
  }

  for(size_t i = 0; i < countof state; i++) cv[i] += state[i];
}
#if ENABLE_X86_EXTENSIONS
#define ADD_BLOCK_EXPANDING_SAVING_X86V2SHA_EXTENSIONS(X) X("ssse3") X("sha")
SET_FEATURES(ADD_BLOCK_EXPANDING_SAVING_X86V2SHA_EXTENSIONS)
static void sha1_add_block_expanding_saving_x86v2sha(
  uint32_t                   cv[static restrict  5]
, const uint32_t UNALIGN      m[static restrict 16]
, uint32_t                    W[static restrict 80]
, sha1_chaining_value    states[static restrict sha1dc_n_needed_states]) {
  static constexpr v16u8 bev4beu8_native = {
    15, 14, 13, 12,  11, 10,  9,  8,   7,  6,  5,  4,   3,  2,  1,  0};
  static constexpr uint8_t v4u32_rev = 0b00'01'10'11;
  // "n" for "negative": at compressor step `i`, the consumed word `W[i]`
  // depends on Wrn16_n1 = {W[i - 16], ..., W[i - 1]}.
  // "r" for "reversed": for some reason, the SHA1 instructions want the vectors
  // to be reversed (like {W[i + 3], W[i + 2], W[i + 1], W[i]}).
  v4u32 Wrn16_n1[4];
  for(size_t i = 0; i < 16; i += 4)
    Wrn16_n1[i / 4] = (v4u32)index_v16u8(loadu_v16u8(&m[i]), bev4beu8_native);
  // now, Wrn16_n1 = {{W[3], W[2], W[1], W[0]}, ...};

  v4u32
    cur_abcd = {sha1_D(cv), sha1_C(cv), sha1_B(cv), sha1_A(cv)},
    old_abcd = (v4u32)_mm_undefined_si128();
  old_abcd[3] = sha1_rotate_left(sha1_E(cv), 2);
  sha1_chaining_value cur_forw;
  uint32_t Wn1_p2[4];
steps:
  STATIC_FOR(signed char i = 0; true; i += 4) {
    sha1_A(cur_forw) = cur_abcd[3];
    sha1_B(cur_forw) = cur_abcd[2];
    sha1_C(cur_forw) = cur_abcd[1];
    sha1_D(cur_forw) = cur_abcd[0];
    sha1_E(cur_forw) = sha1_rotate_right(old_abcd[3], 2);
    sha1_chaining_value cur_back;
    memcpy(cur_back, cur_forw, sizeof cur_forw);

    v4u32 Wrp0_p3;
    if(i < 80) {
      if(i < 16) Wrp0_p3 = Wrn16_n1[i / 4];
      else {
        Wrp0_p3     = Wrn16_n1[0];
        Wrp0_p3     =  sha1msg1(Wrp0_p3, Wrn16_n1[0] = Wrn16_n1[1]);
        Wrp0_p3     = xor_v4u32(Wrp0_p3, Wrn16_n1[1] = Wrn16_n1[2]);
        Wrp0_p3     =  sha1msg2(Wrp0_p3, Wrn16_n1[2] = Wrn16_n1[3]);
        Wrn16_n1[3] = Wrp0_p3;
      }
      *(v4u32 [[gnu::aligned(alignof *W)]]*)&W[i] =
        index_v4u32(Wrp0_p3, v4u32_rev);
      Wn1_p2[1] = Wrp0_p3[3 - 0];
      Wn1_p2[2] = Wrp0_p3[3 - 1];
      Wn1_p2[3] = Wrp0_p3[3 - 2];
      Wrp0_p3 = sha1nexte(old_abcd, Wrp0_p3);
    }

    old_abcd = cur_abcd;
    cur_abcd = sha1rnds4(cur_abcd, Wrp0_p3, i / 20);
    STATIC_FOR(signed char j = 0; true;) {
      if(signed char slot = sha1dc_need_state[i + j]; slot != -1)
        memcpy(states[slot], cur_back, sizeof cur_back);
      if(--j < -1 || i + j < 0) break;
      sha1_step_bw(cur_back, Wn1_p2[1 + j], i + j);
    }
    STATIC_FOR(signed char j = 0; true;) {
      if(i + j >= 80) break steps;
      sha1_step(cur_forw, Wn1_p2[1 + j], i + j);
      if(++j >= 3) break;
      if(signed char slot = sha1dc_need_state[i + j]; slot != -1)
        memcpy(states[slot], cur_forw, sizeof cur_forw);
    }
  }

  for(size_t i = 0; i < countof cur_forw; i++) cv[i] += cur_forw[i];
}
RESET_FEATURES
#endif
void sha1_add_block_expanding_saving [[
  gnu::visibility("hidden")
#if ENABLE_X86_EXTENSIONS
, gnu::ifunc("pick_add_block_expanding_saving")
#endif
]](
  uint32_t                   cv[static restrict  5]
, const uint32_t UNALIGN      m[static restrict 16]
, uint32_t                    W[static restrict 80]
, sha1_chaining_value    states[static restrict sha1dc_n_needed_states])
#if ENABLE_X86_EXTENSIONS
;
#else
{ sha1_add_block_expanding_saving_portable(cv, m, W, states); }
#endif
#if ENABLE_X86_EXTENSIONS
static typeof(sha1_add_block_expanding_saving)
*pick_add_block_expanding_saving() {
  __builtin_cpu_init();
  typeof(sha1_add_block_expanding_saving) *impl =
    sha1_add_block_expanding_saving_portable;
  if(ADD_BLOCK_EXPANDING_SAVING_X86V2SHA_EXTENSIONS(CHECK_FEATURE_AND) true)
    impl = sha1_add_block_expanding_saving_x86v2sha;
  return impl;
}
#endif

// Similar to sha1_add_block, but the caller supplies not the first state but
// the state after `t` words (!!!). The "input"/first state is reconstructed and
// returned beside the output. This may be called a "recompression" function.
static inline void sha1_add_block_predict [[gnu::always_inline]](
  unsigned char t
, uint32_t         cv_in[static restrict  5]
, uint32_t        cv_out[static restrict  5]
, const uint32_t       W[static restrict 80]
, const uint32_t t_state[static restrict  5]) {
  memcpy(cv_in,  t_state, sizeof(sha1_chaining_value));
  memcpy(cv_out, t_state, sizeof(sha1_chaining_value));
  STATIC_FOR(unsigned char i = t; i--;)        sha1_step_bw(cv_in,  W[i], i);
  STATIC_FOR(unsigned char i = t; i < 80; i++)    sha1_step(cv_out, W[i], i);
  for(size_t i = 0; i < countof(sha1_chaining_value); i++)
    cv_out[i] += cv_in[i];
}

// We actually want to specialize sha1_add_block_predict on t.
#define MAKE_SHA1_RECOMPRESS(T) \
  static inline void sha1_recompress_ ## T [[gnu::always_inline]]( \
    uint32_t             cv_in[static restrict  5]                 \
  , uint32_t            cv_out[static restrict  5]                 \
  , const uint32_t           W[static restrict 80]                 \
  , const uint32_t state_ ## T[static restrict  5]) {              \
    sha1_add_block_predict(T, cv_in, cv_out, W, state_ ## T);      \
  }
// have written myself into a corner
// sorry if your compiler blows up
MAKE_SHA1_RECOMPRESS( 0) MAKE_SHA1_RECOMPRESS( 1) MAKE_SHA1_RECOMPRESS( 2)
MAKE_SHA1_RECOMPRESS( 3) MAKE_SHA1_RECOMPRESS( 4) MAKE_SHA1_RECOMPRESS( 5)
MAKE_SHA1_RECOMPRESS( 6) MAKE_SHA1_RECOMPRESS( 7) MAKE_SHA1_RECOMPRESS( 8)
MAKE_SHA1_RECOMPRESS( 9) MAKE_SHA1_RECOMPRESS(10) MAKE_SHA1_RECOMPRESS(11)
MAKE_SHA1_RECOMPRESS(12) MAKE_SHA1_RECOMPRESS(13) MAKE_SHA1_RECOMPRESS(14)
MAKE_SHA1_RECOMPRESS(15) MAKE_SHA1_RECOMPRESS(16) MAKE_SHA1_RECOMPRESS(17)
MAKE_SHA1_RECOMPRESS(18) MAKE_SHA1_RECOMPRESS(19) MAKE_SHA1_RECOMPRESS(20)
MAKE_SHA1_RECOMPRESS(21) MAKE_SHA1_RECOMPRESS(22) MAKE_SHA1_RECOMPRESS(23)
MAKE_SHA1_RECOMPRESS(24) MAKE_SHA1_RECOMPRESS(25) MAKE_SHA1_RECOMPRESS(26)
MAKE_SHA1_RECOMPRESS(27) MAKE_SHA1_RECOMPRESS(28) MAKE_SHA1_RECOMPRESS(29)
MAKE_SHA1_RECOMPRESS(30) MAKE_SHA1_RECOMPRESS(31) MAKE_SHA1_RECOMPRESS(32)
MAKE_SHA1_RECOMPRESS(33) MAKE_SHA1_RECOMPRESS(34) MAKE_SHA1_RECOMPRESS(35)
MAKE_SHA1_RECOMPRESS(36) MAKE_SHA1_RECOMPRESS(37) MAKE_SHA1_RECOMPRESS(38)
MAKE_SHA1_RECOMPRESS(39) MAKE_SHA1_RECOMPRESS(40) MAKE_SHA1_RECOMPRESS(41)
MAKE_SHA1_RECOMPRESS(42) MAKE_SHA1_RECOMPRESS(43) MAKE_SHA1_RECOMPRESS(44)
MAKE_SHA1_RECOMPRESS(45) MAKE_SHA1_RECOMPRESS(46) MAKE_SHA1_RECOMPRESS(47)
MAKE_SHA1_RECOMPRESS(48) MAKE_SHA1_RECOMPRESS(49) MAKE_SHA1_RECOMPRESS(50)
MAKE_SHA1_RECOMPRESS(51) MAKE_SHA1_RECOMPRESS(52) MAKE_SHA1_RECOMPRESS(53)
MAKE_SHA1_RECOMPRESS(54) MAKE_SHA1_RECOMPRESS(55) MAKE_SHA1_RECOMPRESS(56)
MAKE_SHA1_RECOMPRESS(57) MAKE_SHA1_RECOMPRESS(58) MAKE_SHA1_RECOMPRESS(59)
MAKE_SHA1_RECOMPRESS(60) MAKE_SHA1_RECOMPRESS(61) MAKE_SHA1_RECOMPRESS(62)
MAKE_SHA1_RECOMPRESS(63) MAKE_SHA1_RECOMPRESS(64) MAKE_SHA1_RECOMPRESS(65)
MAKE_SHA1_RECOMPRESS(66) MAKE_SHA1_RECOMPRESS(67) MAKE_SHA1_RECOMPRESS(68)
MAKE_SHA1_RECOMPRESS(69) MAKE_SHA1_RECOMPRESS(70) MAKE_SHA1_RECOMPRESS(71)
MAKE_SHA1_RECOMPRESS(72) MAKE_SHA1_RECOMPRESS(73) MAKE_SHA1_RECOMPRESS(74)
MAKE_SHA1_RECOMPRESS(75) MAKE_SHA1_RECOMPRESS(76) MAKE_SHA1_RECOMPRESS(77)
MAKE_SHA1_RECOMPRESS(78) MAKE_SHA1_RECOMPRESS(79) MAKE_SHA1_RECOMPRESS(80)

// Functionally identical to sha1_add_block_predict, except that it only works
// for certain t and is (supposed to be) faster.
static void sha1_recompress_at(
  unsigned char t
, uint32_t        cv_in[static restrict  5]
, uint32_t       cv_out[static restrict  5]
, const uint32_t      W[static restrict 80]
, const uint32_t   t_cv[static restrict  5]) {
  switch(t) {
#define USE_SHA1_RECOMPRESS(N) \
    case N:                                          \
      if(sha1dc_need_state[N] == -1) unreachable();  \
      sha1_recompress_ ## N(cv_in, cv_out, W, t_cv); \
      break;
  USE_SHA1_RECOMPRESS( 0) USE_SHA1_RECOMPRESS( 1) USE_SHA1_RECOMPRESS( 2)
  USE_SHA1_RECOMPRESS( 3) USE_SHA1_RECOMPRESS( 4) USE_SHA1_RECOMPRESS( 5)
  USE_SHA1_RECOMPRESS( 6) USE_SHA1_RECOMPRESS( 7) USE_SHA1_RECOMPRESS( 8)
  USE_SHA1_RECOMPRESS( 9) USE_SHA1_RECOMPRESS(10) USE_SHA1_RECOMPRESS(11)
  USE_SHA1_RECOMPRESS(12) USE_SHA1_RECOMPRESS(13) USE_SHA1_RECOMPRESS(14)
  USE_SHA1_RECOMPRESS(15) USE_SHA1_RECOMPRESS(16) USE_SHA1_RECOMPRESS(17)
  USE_SHA1_RECOMPRESS(18) USE_SHA1_RECOMPRESS(19) USE_SHA1_RECOMPRESS(20)
  USE_SHA1_RECOMPRESS(21) USE_SHA1_RECOMPRESS(22) USE_SHA1_RECOMPRESS(23)
  USE_SHA1_RECOMPRESS(24) USE_SHA1_RECOMPRESS(25) USE_SHA1_RECOMPRESS(26)
  USE_SHA1_RECOMPRESS(27) USE_SHA1_RECOMPRESS(28) USE_SHA1_RECOMPRESS(29)
  USE_SHA1_RECOMPRESS(30) USE_SHA1_RECOMPRESS(31) USE_SHA1_RECOMPRESS(32)
  USE_SHA1_RECOMPRESS(33) USE_SHA1_RECOMPRESS(34) USE_SHA1_RECOMPRESS(35)
  USE_SHA1_RECOMPRESS(36) USE_SHA1_RECOMPRESS(37) USE_SHA1_RECOMPRESS(38)
  USE_SHA1_RECOMPRESS(39) USE_SHA1_RECOMPRESS(40) USE_SHA1_RECOMPRESS(41)
  USE_SHA1_RECOMPRESS(42) USE_SHA1_RECOMPRESS(43) USE_SHA1_RECOMPRESS(44)
  USE_SHA1_RECOMPRESS(45) USE_SHA1_RECOMPRESS(46) USE_SHA1_RECOMPRESS(47)
  USE_SHA1_RECOMPRESS(48) USE_SHA1_RECOMPRESS(49) USE_SHA1_RECOMPRESS(50)
  USE_SHA1_RECOMPRESS(51) USE_SHA1_RECOMPRESS(52) USE_SHA1_RECOMPRESS(53)
  USE_SHA1_RECOMPRESS(54) USE_SHA1_RECOMPRESS(55) USE_SHA1_RECOMPRESS(56)
  USE_SHA1_RECOMPRESS(57) USE_SHA1_RECOMPRESS(58) USE_SHA1_RECOMPRESS(59)
  USE_SHA1_RECOMPRESS(60) USE_SHA1_RECOMPRESS(61) USE_SHA1_RECOMPRESS(62)
  USE_SHA1_RECOMPRESS(63) USE_SHA1_RECOMPRESS(64) USE_SHA1_RECOMPRESS(65)
  USE_SHA1_RECOMPRESS(66) USE_SHA1_RECOMPRESS(67) USE_SHA1_RECOMPRESS(68)
  USE_SHA1_RECOMPRESS(69) USE_SHA1_RECOMPRESS(70) USE_SHA1_RECOMPRESS(71)
  USE_SHA1_RECOMPRESS(72) USE_SHA1_RECOMPRESS(73) USE_SHA1_RECOMPRESS(74)
  USE_SHA1_RECOMPRESS(75) USE_SHA1_RECOMPRESS(76) USE_SHA1_RECOMPRESS(77)
  USE_SHA1_RECOMPRESS(78) USE_SHA1_RECOMPRESS(79) USE_SHA1_RECOMPRESS(80)
  default:
    unreachable();
  }
}

void PROTECTED(process)(
  struct sha1dc_ctx *restrict ctx
, const uint32_t UNALIGN block[static restrict 16]) {
  memcpy(ctx->block_in, ctx->cv, sizeof ctx->cv);
  sha1_add_block_expanding_saving(
    ctx->cv, block, ctx->block_W, ctx->block_state);

  bool detect_coll = expected(ctx->detect_coll, 1);
  if(!detect_coll) return;

  uint8_t dvs[PROTECTED(dvmask_bytes)()];
  bool ubc_check = expected(ctx->ubc_check, 1);
  if(ubc_check) PROTECTED(ubc_check)(ctx->block_W, dvs);
  else for(size_t i = 0; i < countof dvs; i++) dvs[i] = -1;

  bool need_recompress = expected(
    PROTECTED(check_dvmask)(dvs)
  , // empirical false-positive rate of ubc_check when hashing random data
    0.047);
  if(!need_recompress) return;
  for(size_t i = 0; i < PROTECTED(n_disturbance_vectors); i++) {
    if(!(dvs[i / 8] & UINT8_C(1) << i % 8)) continue;

    for(size_t j = 0; j < 80; j++) {
      ctx->twin_W[j]  = ctx->block_W[j];
      ctx->twin_W[j] ^= PROTECTED(disturbance_vectors)[i].message_mask[j];
    }
    size_t quiet_step      = PROTECTED(disturbance_vectors)[i].test_state;
    size_t quiet_step_save = sha1dc_need_state[quiet_step];

    sha1_recompress_at(
      quiet_step
    , ctx->twin_in, ctx->twin_out
    , ctx->twin_W, ctx->block_state[quiet_step_save]);

    if(!memcmp(ctx->twin_out, ctx->cv, sizeof ctx->cv)
    ||    ctx->reduced_round_coll
       && !memcmp(ctx->twin_in, ctx->block_in, sizeof ctx->block_in)) {
      ctx->found_collision = true;

      if(ctx->collision)
        ctx->collision(
          ctx->collision_closure, ctx->bytes
        , ctx->block_in, ctx->twin_in, ctx->block_W, ctx->twin_W);

      if(ctx->do_safe_hash) {
        sha1_add_block(ctx->cv, ctx->block_W);
        sha1_add_block(ctx->cv, ctx->block_W);
      }

      break;
    }
  }
}
EXPORT_PROTECTED(process);
