// © 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>
// SPDX-License-Identifier: MIT
//
// License text available in accompanying file LICENSE.txt, or at
// https://opensource.org/licenses/MIT.
#include <stdcountof.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "x86.h"

#include "sha1_private.h"
#include "core_private.h"
#include "data.h"

// Tweakable
#ifndef ALWAYS_AVX512
# define ALWAYS_AVX512 0
#endif

#define USED_AVX512_FEATURES(X) \
  X("avx512f")    \
  X("avx512bw")   \
  X("avx512vl")   \
  X("avx512vbmi")

#if !ALWAYS_AVX512
// Roughly equivalent to the original from 2017, but relying on an optimizing
// compiler instead of a code generator. For some reason, this version is
// marginally *faster*, even though it's missing some features of the original.
// TODO: Investigate.
//
// Also, this version appears to have much worse variance in runtime, presumably
// because the low probability UBCs after the early return are not grouped by
// DV. (That's one of the features missing from the original.) TODO: make
// parse_bitrel output fancier data.
void PROTECTED(ubc_check_baseline)(
  uint32_t const W[static restrict 80]
, uint8_t        dvmask[static restrict PROTECTED(dvmask_bytes)()]) {
  typedef uint32_t whole_dvmask;
  if(PROTECTED(dvmask_bytes)() > sizeof(whole_dvmask)) abort();
  whole_dvmask possible = -1;
  STATIC_FOR(size_t i = 0; i < countof sha1dc_ubcs; i++) {
    auto ubc = sha1dc_ubcs[i];
    whole_dvmask dvs = {};
    memcpy(&dvs, ubc.dvmask, PROTECTED(dvmask_bytes)());

    char
      common = ubc.i <= ubc.j ? ubc.i : ubc.j,
      left   = ubc.i - common,
      right  = ubc.j - common;

    if(i > 64 && !(possible & dvs)) continue;
    uint32_t
      b1  = W[ubc.a]  >> left,
      b2  = W[ubc.b]  >> right,
      lhs = (b1 ^ b2) >> common & 1,
      eq  = ubc.c ? 0 - lhs : lhs - 1;
    possible &= eq | ~dvs;
    if(i == 64 && !possible) break;
  }
  memcpy(dvmask, &possible, PROTECTED(dvmask_bytes)());
}
EXPORT_PROTECTED(ubc_check_baseline);
#endif

#if ENABLE_X86_EXTENSIONS
SET_FEATURES(USED_AVX512_FEATURES)

// This started holding purely by accident, and it's unclear if it actually
// affects anything. But it's good to keep on eye on.
static_assert(
    offsetof(struct sha1dc_ctx, block_W[sha1dc_avx512_bias])
  % alignof(v16u32) == 0
, "struct sha1dc_ctx::block_W[sha1dc_avx512_bias] is not aligned for AVX-512");

void PROTECTED(ubc_check_avx512)(
  uint32_t const W[static restrict 80]
, uint8_t        out[static restrict PROTECTED(dvmask_bytes)()]) {
  v64u8
    w1 = loadu_v64u8(&W[sha1dc_avx512_bias]),
    w2 = loadu_v64u8(&W[sha1dc_avx512_bias + sizeof w1 / sizeof *W]);

  // The table generator has picked out a vectorizable integer type wide enough
  // to hold a dvmask and used it to arrange the dvmask table.
  // (The type is currently uint32_t and this code is NOT generic over it (e.g.
  // the intrinsic functions have the width in their names), but it is heavily
  // typed to hopefully make it clear what choices depend on what.)
  typedef typeof_unqual(sha1dc_avx512_v64ubc_dvmasks[0][0][0]) whole_dvmask;
  if(PROTECTED(dvmask_bytes)() > sizeof(whole_dvmask)) abort();
  // Accumulator(s) (under OR) for the dvmasks of UBCs that fail.
  //
  // Each incoming mask will go to one of the lanes essentially arbitrarily, so
  // the lanes need to be ORed up into one mask afterwards. A "negative" mask is
  // used over a "positive" one like in the original sha1dc because there is no
  // single instruction on x86 that accomplishes `reg &= ~mem` on x86 (there is
  // only `reg = ~reg & mem`). There is, of course, one for `reg |= mem`. (The
  // alternative is to remove the `~` in `reg &= ~mem` by inverting the dvmask
  // tables statically, but that'd be ugly. TODO: check if GCC can figure out
  // making inverted tables (it does do it for scalar code).)
  whole_dvmask [[gnu::vector_size(64)]] impossible
#if UNROLLING_LOOPS
  // When unrolling, we can avoid zeroing. See use below.
#else
      = {}
#endif
  ;

  // The accumulator register is not nearly big enough to hold 64 dvmasks for 64
  // UBCs. Its actual width, in units of whole_dvmask, is
  constexpr static size_t impossible_dvmasks =
    // countof impossible; // not supported
    sizeof impossible / sizeof impossible[0];
  // Once we evaluate 64 UBCs and have a "vector" (a mask) of 64 results, it'll
  // need to be broken up into this many chunks:
  constexpr static size_t accumulation_chunks = 64 / impossible_dvmasks;

  constexpr static size_t n_v64ubcs = countof sha1dc_avx512_v64ubc_as;
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_bs);
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_ms);
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_ns);
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_cs);
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_dvmasks);
  static_assert(accumulation_chunks == countof *sha1dc_avx512_v64ubc_dvmasks);
  STATIC_FOR(size_t i = 0; i < n_v64ubcs; i++) {
    v64u8
      x = index_2v64u8(w1, w2, sha1dc_avx512_v64ubc_as[i]),
      y = index_2v64u8(w1, w2, sha1dc_avx512_v64ubc_bs[i]);
    __mmask64
      b1 = test_v64u8(x, sha1dc_avx512_v64ubc_ms[i]),
      b2 = test_v64u8(y, sha1dc_avx512_v64ubc_ns[i]),
      // An explicit intrinsic makes GCC push the constant into a kreg
      // instead of pulling the kreg into a GPR
      ne = _kxor_mask64(b1 ^ b2, sha1dc_avx512_v64ubc_cs[i]);
    STATIC_FOR(size_t j = 0; j < accumulation_chunks; j++) {
#if UNROLLING_LOOPS
      // Not necessary for correctness, just cuts out useless work.
      if(64 * i + impossible_dvmasks * j >= countof sha1dc_ubcs) break;
      if(!i && !j)
        // We skipped zeroing `impossible` above, because we can replace the
        // first merge-masking OR with a zeroing-masking load. (This would also
        // not be possible when using a "positive" mask.)
        impossible = load_zv16u32(ne, &sha1dc_avx512_v64ubc_dvmasks[i][j]);
      else
#else
      if(true)
#endif
        impossible = or_mv16u32(
          impossible, ne, impossible, sha1dc_avx512_v64ubc_dvmasks[i][j]);
      ne >>= impossible_dvmasks;
#undef IMPOSSIBLE
    }
  }

  whole_dvmask possible = nor_rv16u32_vl(impossible);
  memcpy(out, &possible, PROTECTED(dvmask_bytes)());
}
EXPORT_PROTECTED(ubc_check_avx512);
RESET_FEATURES

# if !ALWAYS_AVX512
static typeof(PROTECTED(ubc_check)) *pick_ubc_check_impl() {
  typeof(PROTECTED(ubc_check)) *impl = PROTECTED(ubc_check_baseline);
  __builtin_cpu_init();
  if(USED_AVX512_FEATURES(CHECK_FEATURE_AND) true)
    impl = PROTECTED(ubc_check_avx512);
  return impl;
}
# endif
#endif

// TODO: non-ifunc dispatch, for non-GNU/ELF
#if ENABLE_X86_EXTENSIONS && !ALWAYS_AVX512
typeof(sha1dc_ubc_check)
  PROTECTED(ubc_check) [[gnu::ifunc("pick_ubc_check_impl")]],
  sha1dc_ubc_check     [[gnu::ifunc("pick_ubc_check_impl")]];
#else
void PROTECTED(ubc_check)(
  uint32_t const W[static restrict 80]
, uint8_t        dvmask[static restrict PROTECTED(dvmask_bytes)()]) {
# if ALWAYS_AVX512
    sha1dc_ubc_check_avx512
# else
    sha1dc_ubc_check_baseline
# endif
  (W, dvmask);
}
EXPORT_PROTECTED(ubc_check);
#endif
