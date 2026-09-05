/***
* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow (danshu@microsoft.com)
* Distributed under the MIT Software License.
* See accompanying file LICENSE.txt or copy at
* https://opensource.org/licenses/MIT
***/

#include <limits.h>
#include <stdbit.h>
#include <stdcountof.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#ifndef SHA1DC_INIT_SAFE_HASH_DEFAULT
#define SHA1DC_INIT_SAFE_HASH_DEFAULT 1
#endif

#include "sha1.h"
#include "ubc_check.h"

#if (defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || \
     defined(i386) || defined(__i386) || defined(__i386__) || defined(__i486__)  || \
     defined(__i586__) || defined(__i686__) || defined(_M_IX86) || defined(__X86__) || \
     defined(_X86_) || defined(__THW_INTEL__) || defined(__I86__) || defined(__INTEL__) || \
     defined(__386) || defined(_M_X64) || defined(_M_AMD64))
#define SHA1DC_ON_INTEL_LIKE_PROCESSOR
#endif

#ifndef SHA1DC_ENDIAN
# ifndef __STDC_ENDIAN_NATIVE__
#   error "SHA1DC_ENDIAN not defined and __STDC_ENDIAN_NATIVE__ not found..."
# endif
# define SHA1DC_ENDIAN __STDC_ENDIAN_NATIVE__
#endif

#ifndef SHA1DC_FORCE_ALIGNED_ACCESS
# ifdef SHA1DC_ON_INTEL_LIKE_PROCESSOR
#   define SHA1DC_ALLOW_UNALIGNED_ACCESS
# endif
#endif
#ifdef SHA1DC_ALLOW_UNALIGNED_ACCESS
# define UNALIGN [[gnu::aligned(1)]]
# define sha1_load8_maybe_unaligned_beu32 sha1_load8_beu32
#else
# define UNALIGN
# define sha1_load8_maybe_unaligned_beu32 sha1_load8_aligned_beu32
#endif

#if __STDC_VERSION_STDBIT_H__ >= 202609L
# define sha1_rotate_left          stdc_rotate_left
# define sha1_rotate_right         stdc_rotate_right
# define sha1_load8_aligned_beu32  stdc_load8_aligned_beu32
# define sha1_store8_aligned_beu32 stdc_store8_aligned_beu32
# define sha1_load8_beu32          stdc_load8_beu32
# define sha1_store8_beu32         stdc_store8_beu32
#else
static inline uint32_t sha1_rotate_left(uint32_t x, int s) {
  s &= 31;
  return x << s | x >> 32 - (s ? s : 32);
}
static inline uint32_t sha1_rotate_right(uint32_t x, int s) {
  return sha1_rotate_left(x, -(s & 31));
}
# define sha1_load8_aligned_beu32  sha1_load8_beu32
# define sha1_store8_aligned_beu64 sha1_store8_beu64
static inline uint32_t sha1_load8_beu32(const unsigned char p[static 4]) {
  uint32_t thou = p[0], hund = p[1], tens = p[2], ones = p[3];
  return thou << 24 | hund << 16 | tens << 8 | ones;
}
static inline void sha1_store8_beu64(uint64_t x, unsigned char p[static 8]) {
  for(char i = 64; (i -= 8) + 8;) *p++ = x >> i;
}
static inline void sha1_store8_beu32(uint32_t x, unsigned char p[static 4]) {
  for(char i = 32; (i -= 8) + 8;) *p++ = x >> i;
}
#endif

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

#ifdef SHA1DC_EXPORT_PLAIN_SHA1
# define DECLARE_PLAIN_SHA1(D) D [[gnu::visibility("protected")]]
#else
# define DECLARE_PLAIN_SHA1(D) static D [[maybe_unused]]
#endif

// SHA-1's compression function (including the feed-forward), which takes an
// expanded message block.
DECLARE_PLAIN_SHA1(void sha1_add_block)(
  uint32_t       cv[static restrict 5]
, const uint32_t  W[static restrict 80]) {
  sha1_chaining_value_t state;
  memcpy(state, cv, sizeof state);

#pragma GCC unroll 999
  for(unsigned char i = 0; i < 80; i++) sha1_step(state, W[i], i);

  for(size_t i = 0; i < countof state; i++) cv[i] += state[i];
}
// SHA-1's update function, including the message read-in (i.e. endianness
// handling) and expansion.
DECLARE_PLAIN_SHA1(void sha1_add_block_expanding)(
  uint32_t               cv[static restrict 5]
, const uint32_t UNALIGN  m[static restrict 16]) {
  sha1_expanded_block_t W;
  sha1_chaining_value_t state;
  memcpy(state, cv, sizeof state);

#pragma GCC unroll 999
  for(unsigned char i = 0; i < 80; i++) {
    W[i] =
        i < 16
      ? sha1_load8_maybe_unaligned_beu32((const unsigned char*)(m + i))
      : sha1_expand_one(W + i);
    sha1_step(state, W[i], i);
  }

  for(size_t i = 0; i < countof state; i++) cv[i] += state[i];
}

// The same as sha1_add_block_expanding, but saving W and some states.
DECLARE_PLAIN_SHA1(void sha1_add_block_expanding_saving)(
  uint32_t                   cv[static restrict  5]
, const uint32_t UNALIGN      m[static restrict 16]
, uint32_t                    W[static restrict 80]
, sha1_chaining_value_t  states[static restrict sha1dc_n_needed_states]) {
  sha1_chaining_value_t  state;
  memcpy(state, cv, sizeof state);
  size_t saved = 0;

#pragma GCC unroll 999
  for(unsigned char i = 0; true; i++) {
    if(sha1dc_need_state[i] != -1) {
      if((size_t)sha1dc_need_state[i] != saved) unreachable();
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

// Similar to sha1_add_block, but the caller supplies not the first state but
// the state after `t` words (!!!). The "input"/first state is reconstructed and
// returned beside the output. This may be called a "recompression" function.
static inline void sha1_add_block_predict [[gnu::always_inline]](
  unsigned char t
, uint32_t cv_in[static restrict 5], uint32_t cv_out[static restrict 5]
, const uint32_t W[static restrict 80]
, const uint32_t state_t[static restrict 5]) {
  memcpy(cv_in,  state_t, sizeof(sha1_chaining_value_t));
  memcpy(cv_out, state_t, sizeof(sha1_chaining_value_t));
#pragma GCC unroll 999
  for(unsigned char i = t; i--;)        sha1_step_bw(cv_in,  W[i], i);
#pragma GCC unroll 999
  for(unsigned char i = t; i < 80; i++)    sha1_step(cv_out, W[i], i);
  for(size_t i = 0; i < countof(sha1_chaining_value_t); i++)
    cv_out[i] += cv_in[i];
}

// We actually want to specialize sha1_add_block_predict on t.
#define MAKE_SHA1_RECOMPRESS(T) \
  static inline void sha1_recompress_ ## T [[gnu::always_inline]](        \
    uint32_t cv_in[static restrict 5], uint32_t cv_out[static restrict 5] \
  , const uint32_t W[static restrict 80]                                  \
  , const uint32_t state_ ## T[static restrict 5]) {                      \
    sha1_add_block_predict(T, cv_in, cv_out, W, state_ ## T);             \
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
, uint32_t cv_in[static restrict 5], uint32_t cv_out[static restrict 5]
, const uint32_t W[static restrict 80]
, const uint32_t cv_t[static restrict 5]) {
  switch(t) {
#define USE_SHA1_RECOMPRESS(N) \
    case N:                                          \
      if(sha1dc_need_state[N] == -1) unreachable();  \
      sha1_recompress_ ## N(cv_in, cv_out, W, cv_t); \
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

static void sha1dc_process(
  struct sha1dc_ctx *restrict ctx
, const uint32_t block[static restrict 16]) {
  memcpy(ctx->ihv1, ctx->ihv, sizeof ctx->ihv);
  sha1_add_block_expanding_saving(ctx->ihv, block, ctx->m1, ctx->states);

  if(!ctx->detect_coll) return;

  uint8_t dvs[sha1dc_dvmask_bytes()];
  if(ctx->ubc_check) sha1dc_ubc_check(ctx->m1, dvs);
  else for(size_t i = 0; i < countof dvs; i++) dvs[i] = -1;

  if(!sha1dc_check_dvmask(dvs)) return;
  for(size_t i = 0; i < sha1dc_n_disturbance_vectors; i++) {
    if(!(dvs[i / 8] & UINT8_C(1) << i % 8)) continue;
    for(size_t j = 0; j < 80; j++) {
      ctx->m2[j] = ctx->m1[j];
      ctx->m2[j] ^= sha1dc_disturbance_vectors[i].message_mask[j];
    }
    size_t saved = sha1dc_need_state[sha1dc_disturbance_vectors[i].test_t];
    if(saved >= sha1dc_n_needed_states) unreachable();

    sha1_chaining_value_t cv_alternate;
    sha1_recompress_at(
      sha1dc_disturbance_vectors[i].test_t
    , ctx->ihv2, cv_alternate
    , ctx->m2, ctx->states[saved]);

    if(!memcmp(cv_alternate, ctx->ihv, sizeof ctx->ihv)
    ||    ctx->reduced_round_coll
       && !memcmp(ctx->ihv2, ctx->ihv1, sizeof ctx->ihv1)) {
      ctx->found_collision = 1;

      if (ctx->safe_hash) {
        sha1_add_block(ctx->ihv, ctx->m1);
        sha1_add_block(ctx->ihv, ctx->m1);
      }

      break;
    }
  }
}

void sha1dc_init(struct sha1dc_ctx *ctx) {
  ctx->bytes = 0;
  ctx->ihv[0] = 0x67452301;
  ctx->ihv[1] = 0xEFCDAB89;
  ctx->ihv[2] = 0x98BADCFE;
  ctx->ihv[3] = 0x10325476;
  ctx->ihv[4] = 0xC3D2E1F0;
  ctx->found_collision = 0;
  ctx->safe_hash = SHA1DC_INIT_SAFE_HASH_DEFAULT;
  ctx->ubc_check = 1;
  ctx->detect_coll = 1;
  ctx->reduced_round_coll = 0;
  ctx->collision = NULL;
}

void sha1dc_set_safe(struct sha1dc_ctx *ctx, bool safe_hash) {
  ctx->safe_hash = safe_hash;
}
void sha1dc_set_use_ubc(struct sha1dc_ctx *ctx, bool ubc_check) {
  ctx->ubc_check = ubc_check;
}
void sha1dc_set_detect_coll(struct sha1dc_ctx *ctx, bool detect_coll) {
  ctx->detect_coll = detect_coll;
}
void sha1dc_set_detect_reduced_round_coll(
  struct sha1dc_ctx *ctx, bool reduced_round_coll) {
  ctx->reduced_round_coll = reduced_round_coll;
}

void sha1dc_set_callback(
  struct sha1dc_ctx *ctx
, sha1dc_collision_handler_t *collision, void *closure) {
  ctx->collision = collision;
  ctx->collision_closure = closure;
}

void sha1dc_ingest(
  size_t n; struct sha1dc_ctx *restrict ctx
, const unsigned char buf[static restrict n], size_t n) {
  if(!n) return;

  unsigned char held = ctx->bytes % sizeof ctx->buffer;
  unsigned char need = sizeof ctx->buffer - held;

  if(held && n >= need) {
    ctx->bytes += need;
    memcpy((char*)ctx->buffer + held, buf, need);
    sha1dc_process(ctx, ctx->buffer);
    buf        += need;
    n          -= need;
    held        = 0;
  }
  while(n >= sizeof ctx->buffer) {
    ctx->bytes += sizeof ctx->buffer;

#ifdef SHA1DC_ALLOW_UNALIGNED_ACCESS
    sha1dc_process(ctx, (uint32_t*)buf);
#else
    memcpy(ctx->buffer, buf, sizeof ctx->buffer);
    sha1dc_process(ctx, ctx->buffer);
#endif
    buf += sizeof ctx->buffer;
    n   -= sizeof ctx->buffer;
  }
  if(n > 0) {
    ctx->bytes += n;
    memcpy((char*)ctx->buffer + held, buf, n);
  }
}

static const unsigned char sha1_padding[64] = {1 << 7};
bool sha1dc_finish(
  unsigned char output[static restrict 20]
, struct sha1dc_ctx *restrict ctx) {
  uint32_t last = ctx->bytes & 63;
  uint32_t padn = (last < 56) ? (56 - last) : (120 - last);
  sha1dc_ingest(ctx, sha1_padding, padn);

  uint64_t bits = 8 * (ctx->bytes - padn);
  sha1_store8_aligned_beu64(bits, (unsigned char*)(ctx->buffer + 14));
  sha1dc_process(ctx, ctx->buffer);

  for(size_t i = 0; i < countof ctx->ihv; i++)
    sha1_store8_beu32(ctx->ihv[i], output + sizeof(uint32_t) * i);
  return ctx->found_collision;
}
