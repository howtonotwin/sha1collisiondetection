// Tweakables
#ifndef ENABLE_AVX512
# define ENABLE_AVX512 1
#endif
#ifndef ALWAYS_AVX512
# define ALWAYS_AVX512 0
#endif
// Not "is -funroll-loops on?" but rather "will '#pragma GCC unroll' work?" If
// this is off, unroll pragmas are not emitted and no extra conditionals are
// emitted into loops. If sensitive loops still get unrolled (in the case where
// this is off), the code will be a little suboptimal (few percent slower) If
// this is on and sensitive loops are not unrolled (e.g. `-Og` makes GCC ignore
// unroll pragmas, or MSVC does not heed unroll requests at all), the code will
// be *awful* (~70% percent slower). Do not allow this to happen.
#ifndef UNROLLING_LOOPS
  // This is just a best guess
# define UNROLLING_LOOPS __GNUC__ && __OPTIMIZE__ && !__OPTIMIZE_SIZE__
#endif
#define USED_AVX512_FEATURES(X) \
  X("avx512f")    \
  X("avx512bw")   \
  X("avx512dq")   \
  X("avx512vl")   \
  X("avx512vbmi")

// Headers
#include <stdbit.h>
#include <stdcountof.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if ENABLE_AVX512
# include <immintrin.h>
#endif

#include "ubc_check.h"

// Consuming the output of parse_bitrel (and renaming things)
#define sha1dc_disturbance_vector_dv_class     class
#define sha1dc_disturbance_vector_k            k
#define sha1dc_disturbance_vector_b            b
#define sha1dc_disturbance_vector_test_t       test_t
#define sha1dc_disturbance_vector_message_mask message_mask
#define sha1dc_ubc_a      a
#define sha1dc_ubc_b      b
#define sha1dc_ubc_i      i
#define sha1dc_ubc_j      j
#define sha1dc_ubc_c      c
#define sha1dc_ubc_dvmask dvmask
#include "ubc_check.inc"
#undef sha1dc_disturbance_vector_dv_class
#undef sha1dc_disturbance_vector_k
#undef sha1dc_disturbance_vector_b
#undef sha1dc_disturbance_vector_test_t
#undef sha1dc_disturbance_vector_message_mask
#undef sha1dc_ubc_a
#undef sha1dc_ubc_b
#undef sha1dc_ubc_i
#undef sha1dc_ubc_j
#undef sha1dc_ubc_c
#undef sha1dc_ubc_dvmask

// Now set up some preprocessor magic
#define PRAGMA_WORDS(...)            _Pragma(# __VA_ARGS__)
#define STRICT1(M, x)                M(x)
#define FEATURE_INTO_TARGET(feature) feature ","
#define SET_FEATURES(F)              \
  STRICT1(PRAGMA_WORDS, GCC target F(FEATURE_INTO_TARGET))

// Now code.
#if !ALWAYS_AVX512
// This is actually *faster* than the one from 2017 already. Unrolling! But e.g.
// MSVC is obstinate and won't unroll this, because it can't see it gets faster,
// so generating unrolled source code is still a good next step.
void sha1dc_ubc_check_baseline(
  uint32_t const W[static restrict 80]
, uint8_t        dvmask[static restrict sha1dc_dvmask_bytes()]) {
  uint32_t possible = -1;
  if(sha1dc_dvmask_bytes() != sizeof possible) abort();
  #pragma GCC unroll 9999
  for(size_t i = 0; i < countof sha1dc_ubcs; i++) {
    auto ubc = sha1dc_ubcs[i];

    typedef typeof(possible) [[gnu::aligned(alignof(ubc.dvmask))]] dvmask_t;
    auto dvs = *(const dvmask_t*)ubc.dvmask;

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
  memcpy(dvmask, &possible, sha1dc_dvmask_bytes());
}
#endif

#if ENABLE_AVX512
# pragma GCC push_options
  SET_FEATURES(USED_AVX512_FEATURES)

typedef uint32_t [[gnu::vector_size(64)]] v16u32;
typedef uint8_t  [[gnu::vector_size(64)]] v64u8;

  // Format given inline-asm named operands for use in an x86 assembly template.
# define AVX512_ARGS3K(dst, k, src1, src2) \
    "\t" /* go from opcode mnemonic column to operands */ \
    "{"  /* AT&T dialect */                               \
      "%[" # src2 "], "                                   \
      "%[" # src1 "], "                                   \
      "%[" # dst  "]" "%{"                                \
        "%[" # k "]"                                      \
      "%}"                                                \
    "|"  /* Intel dialect */                              \
      "%[" # dst  "]" "%{"                                \
        "%[" # k "]"                                      \
      "%}, "                                              \
      "%[" # src1  "], "                                  \
      "%[" # src2  "]"                                    \
    "}"
// The AVX-512 intrinsics don't have a surefire way of expressing the special
// behavior of the masked instructions with memory operands of totally avoiding
// (the appearance of) touching the masked out memory regions. (The masked load
// intrinsics are exceptional in that they can express this, but then GCC
// doesn't turn the explicit masked loads back into memory operands. GCC also
// has several other shortcomings with optimizing the intrinsics.)
// So: explicit assembly!
// "OR mask vector of 16 uint32_t memory"
static inline v16u32 or_mv16u32_mem [[gnu::always_inline, gnu::artificial]](
  v16u32 dst, __mmask16 k, v16u32 src1, uint32_t const *src2) {
  const v16u32 [[gnu::aligned(alignof *src2)]] *p = (void const*)src2;
  // trust the user
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
  __asm__(
    "vpord" AVX512_ARGS3K(dst, k, src1, p)
  : [dst]"+v"(dst)
  : [k]"Yk"(k), [src1]"v"(src1), [p]"m"(*p));
#pragma GCC diagnostic pop
  return dst;
}

void sha1dc_ubc_check_avx512(
  uint32_t const W[static restrict 80]
, uint8_t        out[static restrict sha1dc_dvmask_bytes()]) {
  const v64u8 [[gnu::aligned(alignof *W)]] *Wv64 =
    (const void*)&W[sha1dc_avx512_bias];
  v64u8 w1 = Wv64[0], w2 = Wv64[1];

  // The table generator has picked out a vectorizable integer type wide enough
  // to hold a dvmask and used it to arrange the dvmask table.
  // (The type is currently uint32_t and this code is NOT generic over it (e.g.
  // the intrinsic functions have the width in their names), but it is heavily
  // typed to hopefully make it clear what choices depend on what.)
  typedef typeof_unqual(*sha1dc_avx512_dvmasks) dvmask_t;
  // Accumulator(s) (under OR) for the dvmasks of UBCs that fail.
  //
  // Each incoming mask will go to one of the lanes essentially arbitrarily, so
  // the lanes need to be ORed up into one mask afterwards. A "negative" mask is
  // used over a "positive" one like in the original sha1dc because there is no
  // single instruction on x86 that accomplishes `reg &= ~mem` on x86 (there is
  // only `reg = ~reg & mem`). There is, of course, one for `reg |= mem`. (The
  // alternative is to remove the `~` in `reg &= ~mem` by inverting the dvmask
  // tables statically, but that'd be ugly.)
  dvmask_t [[gnu::vector_size(64)]]
#if UNROLLING_LOOPS
  // Creating one long dependency chain on one accumulator makes the latency of
  // this whole function a bit higher than it needs to be. We can instead
  // alternate between two accumulators and join them up at the end. This takes
  // advantage of the fact that most (all?) processors with AVX-512 can do two
  // 512-bit ORs at the same time. In exchange, we need one more OR to join the
  // accumulators at reduction.
  //
  // All this is only going to be profitable if alternating between accumulators
  // does not involve adding conditional instructions. For this code, that means
  // the loops need to be unrolled.
  //
  // NB: Empirically, doing this appears to have a tiny worsening effect on
  //     throughput (cycles/call or MB/s), <0.5 cycles/call (out of 20-30).
  //     Theoretically (according to llvm-mca, for this author's particular
  //     core), if there were no external interference, there should be no
  //     difference in throughput.
  impossible0, impossible1
  // When unrolling, we can also avoid zeroing. See use below.

  // This is for (static) calculations before we have the loop counter for
  // selecting the accumulator.
# define IMPOSSIBLE impossible0
#else
  impossible = {}
# define IMPOSSIBLE impossible
#endif
  ;
  // The accumulator register is not nearly big enough to hold 64 dvmasks for 64
  // UBCs. Its actual width, in units of dvmask_t, is
  constexpr static size_t impossible_dvmasks =
    // countof IMPOSSIBLE; // not supported
    sizeof IMPOSSIBLE / sizeof IMPOSSIBLE[0];
  // Once we evaluate 64 UBCs and have a "vector" (a mask) of 64 results, it'll
  // need to be broken up into this many chunks:
  constexpr static size_t accumulation_chunks = 64 / impossible_dvmasks;

  constexpr static size_t n_v64ubcs = countof sha1dc_avx512_v64ubc_as;
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_bs);
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_ms);
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_ns);
  static_assert(n_v64ubcs == countof sha1dc_avx512_v64ubc_cs);
  static_assert(
      64 * n_v64ubcs
    >= // XXX: padding UBCs need not have dvmasks!
      countof sha1dc_avx512_dvmasks);
  static_assert(countof sha1dc_ubcs == countof sha1dc_avx512_dvmasks);
#if UNROLLING_LOOPS
#pragma GCC unroll 999
#endif
  for(size_t i = 0; i < n_v64ubcs; i++) {
    v64u8
      x  = (typeof(x))_mm512_permutex2var_epi8(
        (__m512i)w1
      , (__m512i)sha1dc_avx512_v64ubc_as[i]
      , (__m512i)w2),
      y  = (typeof(y))_mm512_permutex2var_epi8(
        (__m512i)w1
      , (__m512i)sha1dc_avx512_v64ubc_bs[i]
      , (__m512i)w2);
    __mmask64
      b1 = _mm512_test_epi8_mask(
        (__m512i)x
      , (__m512i)sha1dc_avx512_v64ubc_ms[i]),
      b2 = _mm512_test_epi8_mask(
        (__m512i)y
      , (__m512i)sha1dc_avx512_v64ubc_ns[i]),
      ne = _kxor_mask64(_kxor_mask64(b1, b2), sha1dc_avx512_v64ubc_cs[i]);
#if UNROLLING_LOOPS
#pragma GCC unroll 999
#endif
    for(size_t j = 0; j < accumulation_chunks; j++) {
#if UNROLLING_LOOPS
      // Not necessary for correctness, just cuts off the unrolling. (Actually,
      // forming the out-of-bounds pointer below is instant UB in ISO C, though
      // GCC (and really any "normal" x86 compiler) will not treat it as such,
      // since the architecture doesn't treat pointers very specially.)
      if(64 * i + impossible_dvmasks * j >= countof sha1dc_avx512_dvmasks)
        break;

      // Make the alternating accumulator transparent to the loop body.
# undef  IMPOSSIBLE
# define IMPOSSIBLE 0[j % 2 == 0 ? &impossible0 : &impossible1]
      if(!i && j < 2)
        // We skipped zeroing IMPOSSIBLE above, because we can replace the first
        // merge-masking OR with a zeroing-masking load.
        IMPOSSIBLE = (typeof(IMPOSSIBLE))_mm512_maskz_load_epi32(
          ne
        , &sha1dc_avx512_dvmasks[64 * i + impossible_dvmasks * j]);
      else
#else
      if(true)
#endif
        IMPOSSIBLE = or_mv16u32_mem(
          IMPOSSIBLE, ne, IMPOSSIBLE
        , &sha1dc_avx512_dvmasks[64 * i + impossible_dvmasks * j]);
      ne >>= impossible_dvmasks;
    }
  }

#if UNROLLING_LOOPS
# undef  IMPOSSIBLE
# define IMPOSSIBLE impossible0
  IMPOSSIBLE = impossible0 | impossible1;
#endif
#if !__OPTIMIZE__
  // This line ends in the instructions
  //     vpord       xmmA, xmmB, xmmA             # fold up the pairs of u32
  //     vpternlogd  xmmA, xmmA, xmmA, 0b01010101 # "xmmA = !xmmA"
  // This is rather silly, since those could be the one instruction
  //     vpternlogd  xmmA, xmmA, xmmB, 0b00010001 # "xmmA = ~(xmmA | xmmB)"
  // There's also a pointless mov somewhere in there...
  dvmask_t possible = ~_mm512_reduce_or_epi32((__m512i)IMPOSSIBLE);
#else
  // If you want something done right, do it yourself!
  // (Maybe one day this block can be removed.)
  dvmask_t [[gnu::vector_size(32)]] half = (typeof(half))_mm256_or_epi32(
    _mm512_extracti32x8_epi32((__m512i)IMPOSSIBLE, 0)
  , _mm512_extracti32x8_epi32((__m512i)IMPOSSIBLE, 1));
  dvmask_t [[gnu::vector_size(16)]] quarter = (typeof(quarter))_mm_or_epi32(
    _mm256_extracti32x4_epi32((__m256i)half, 0)
  , _mm256_extracti32x4_epi32((__m256i)half, 1));
  // Keep going in the vector unit instead of extracting to GPR (expensive).
  dvmask_t [[gnu::vector_size(16)]] eighths = (typeof(eighths))_mm_or_epi32(
    (__m128i)quarter
  , _mm_shuffle_epi32(
      (__m128i)quarter
    , 0b01'00'11'10 /* [1, 0, 3, 2] "swap upper u64 with lower u64" */));
  dvmask_t [[gnu::vector_size(16)]] up16th = (typeof(up16th))_mm_shuffle_epi32(
    (__m128i)eighths
  , 0b01'01'01'01 /* [1, 1, 1, 1] "broadcast upper u32 of lower u64" */);
  // Final reduction of impossible and "possible = ~impossible;", at once.
  dvmask_t possible =
    _mm_ternarylogic_epi32(
      _mm_undefined_si128(), (__m128i)eighths, (__m128i)up16th
    , ~(_MM_TERNLOG_B | _MM_TERNLOG_C))
  [0];
#endif
  memcpy(out, &possible, sha1dc_dvmask_bytes());
}
# pragma GCC pop_options

# if !ALWAYS_AVX512
static typeof(sha1dc_ubc_check) *pick_ubc_check_impl
[[gnu::no_sanitize("all")]]() {
  typeof(sha1dc_ubc_check) *impl = sha1dc_ubc_check_baseline;
  __builtin_cpu_init();
#   if defined(__GNUC__) || defined(__clang__)
#     define CHECK_FEATURE_AND(f) __builtin_cpu_supports(f) &&
  // Since GCC 8, __builtin_cpu_supports checks relevant OS-support flags, so
  // just using it is enough.
  if(USED_AVX512_FEATURES(CHECK_FEATURE_AND) true) impl = sha1dc_ubc_check_avx512;
#   else
#     error "Don't know how to check for AVX-512 with this compiler/platform."
#   endif
  return impl;
}
# endif
#endif

void sha1dc_ubc_check
#if ENABLE_AVX512 && !ALWAYS_AVX512
  [[gnu::ifunc("pick_ubc_check_impl")]]
#endif
( uint32_t const W[static restrict 80]
, uint8_t        dvmask[static restrict sha1dc_dvmask_bytes()])
#if ENABLE_AVX512 && !ALWAYS_AVX512
;
#else
{
# if ALWAYS_AVX512
    sha1dc_ubc_check_avx512
# else
    sha1dc_ubc_check_baseline
# endif
  (W, dvmask);
}
#endif

bool sha1dc_check_dvmask(
  const uint8_t dvmask[static restrict sha1dc_dvmask_bytes()]) {
  uint32_t buf;
  for(size_t i = 0; i < sha1dc_dvmask_bytes(); i += sizeof buf) {
    memcpy(&buf, dvmask, sizeof buf);
    if(buf) return true;
  }
  return false;
}
