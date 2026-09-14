// Tweakables
#ifndef ENABLE_AVX512
  // Similar to but different from the check in sha1.c
# if defined __amd64__ || defined __amd64 || defined __x86_64__ || \
     defined __x86_64  || defined _M_X64  || defined _M_AMD64
#   define ENABLE_AVX512 1
# endif
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
# define UNROLLING_LOOPS (__OPTIMIZE__ && !__OPTIMIZE_SIZE__)
#endif
// see use, below
#ifndef PARALLEL_ACCUMULATORS
# if UNROLLING_LOOPS
#   define PARALLEL_ACCUMULATORS 2
# else
#   define PARALLEL_ACCUMULATORS 1
# endif
#endif
#define USED_AVX512_FEATURES(X) \
  X("avx512f")    \
  X("avx512bw")   \
  X("avx512dq")   \
  X("avx512vl")   \
  X("avx512vbmi")

// Headers
#include <stdcountof.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if ENABLE_AVX512
# include <immintrin.h>
#endif

#include "sha1_private.h"
#include "core_private.h"
#include "data.h"

// Now set up enabling processor features for delimited regions of code.
#define PRAGMA_WORDS(...)            _Pragma(# __VA_ARGS__)
#define FEATURE_INTO_TARGET(feature) feature ","
#define SET_FEATURES(F) \
   _Pragma("GCC push_options") \
   STRICT1(PRAGMA_WORDS, GCC target F(FEATURE_INTO_TARGET))
#define RESET_FEATURES  _Pragma("GCC pop_options")

// Now code.
#if !ALWAYS_AVX512
// This, is roughly equivalent to the one from 2017 due to the (forced) total
// unrolling and then the ensuing constant propagation. Actually, this one is
// marginally *faster*, even though it's missing some features of the original.
// TODO: This warrants investigation.
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
#pragma GCC unroll 999
  for(size_t i = 0; i < countof sha1dc_ubcs; i++) {
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

#if ENABLE_AVX512
SET_FEATURES(USED_AVX512_FEATURES)

// Setting up vector types ("vNuM").
// Note: <immintrin.h> __mmNNNi types can be read from objects of any type,
//       with similar rules to standard C char.
# define U(M) uint ## M ## _t
# define V(N, M) U(M) __attribute__((vector_size(N * sizeof(U(M)))))
typedef V(64,  8) v64u8;
typedef V(16, 32) v16u32;
# undef V
# undef U

static_assert(
    offsetof(struct sha1dc_ctx, block_W[sha1dc_avx512_bias])
  % alignof(v16u32) == 0
, "struct sha1dc_ctx::block_W[sha1dc_avx512_bias] is not aligned for AVX-512");

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
// GCC doesn't seem to understand that it can make the dst and src1 operands of
// an AVX-512 instruction generated from an intrinisic the same. This causes it
// to sprinkle useless movs to copy src1 into dst (even though the remaining
// copy of the old value is never used again). But it does understand how to get
// things right for an inline asm statement. Go figure.
// "OR mask vector 16 uint32_t memory"
static inline v16u32 or_mv16u32_mem [[gnu::always_inline, gnu::artificial]](
  v16u32 dst, __mmask16 k, v16u32 src1, v16u32 const *src2) {
  __asm__(
    "vpord" AVX512_ARGS3K(dst, k, src1, src2)
  : [dst]"+v"(dst)
  : [k]"Yk"(k), [src1]"v"(src1), [src2]"m"(*src2));
  return dst;
}

void PROTECTED(ubc_check_avx512)(
  uint32_t const W[static restrict 80]
, uint8_t        out[static restrict PROTECTED(dvmask_bytes)()]) {
  v64u8
    w1 = (typeof(w1))_mm512_loadu_epi8(
      &W[sha1dc_avx512_bias]),
    w2 = (typeof(w2))_mm512_loadu_epi8(
      &W[sha1dc_avx512_bias + sizeof w1 / sizeof *W]);

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
  // tables statically, but that'd be ugly.)
  __attribute__((vector_size(64))) whole_dvmask impossible[
    // Creating one long dependency chain on one accumulator makes the latency
    // of this whole function a bit higher than it needs to be. We can instead
    // alternate between two accumulators and join them up at the end. This
    // takes advantage of the fact that most (all?) processors with AVX-512 can
    // do two 512-bit ORs at the same time. In exchange, we need one more OR to
    // join the accumulators at reduction.
    //
    // All this is only going to be profitable if alternating between
    // accumulators does not involve adding conditional instructions. For this
    // code, that means the loops need to be unrolled. (Hence the defaults at
    // the top of the file).
    //
    // NB: In a microbenchmark testing just ubc_check, doing this appears to
    //     have a tiny worsening effect on throughput, <0.5 cycles/call (out of
    //     20-30). Theoretically (according to llvm-mca, for this author's
    //     particular core), if there were no external interference, there
    //     should be no difference in throughput. In context,
    //     PARALLEL_ACCUMULATORS=2 produces a slightly faster (~1-3%, in MB/s)
    //     sha1dcsum. The next few values up have no clear effect.
    PARALLEL_ACCUMULATORS]
#if !UNROLLING_LOOPS
      = {}
#endif
  // When unrolling, we can also avoid zeroing. See use below.
  ;

  // The accumulator register is not nearly big enough to hold 64 dvmasks for 64
  // UBCs. Its actual width, in units of whole_dvmask, is
  constexpr static size_t impossible_dvmasks =
    // countof *impossible; // not supported
    sizeof *impossible / sizeof (*impossible)[0];
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
      ne = _kxor_mask64(
        _kxor_mask64(b1, b2)
      , sha1dc_avx512_v64ubc_cs[i]);
#if UNROLLING_LOOPS
#pragma GCC unroll 999
#endif
    for(size_t j = 0; j < accumulation_chunks; j++) {
      // Abbreviation for the alternating accumulator
#define IMPOSSIBLE \
    impossible[(accumulation_chunks * i + j) % PARALLEL_ACCUMULATORS]
#if UNROLLING_LOOPS
      // Not necessary for correctness, just cuts out useless work.
      if(64 * i + impossible_dvmasks * j >= countof sha1dc_ubcs) break;
      if(accumulation_chunks * i + j < PARALLEL_ACCUMULATORS)
        // We skipped zeroing IMPOSSIBLE above, because we can replace the first
        // merge-masking OR with a zeroing-masking load.
        IMPOSSIBLE = (typeof(IMPOSSIBLE))_mm512_maskz_load_epi32(
          ne, &sha1dc_avx512_v64ubc_dvmasks[i][j]);
      else
#else
      if(true)
#endif
        IMPOSSIBLE = or_mv16u32_mem(
          IMPOSSIBLE, ne, IMPOSSIBLE, &sha1dc_avx512_v64ubc_dvmasks[i][j]);
      ne >>= impossible_dvmasks;
#undef  IMPOSSIBLE
    }
  }

  for(size_t i = 1; i < PARALLEL_ACCUMULATORS; i++)
    *impossible |= impossible[i];
#if !__OPTIMIZE__
  // GCC ends this line in the instructions
  //     vpord       xmmA, xmmB, xmmA             # fold up the pairs of u32
  //     vpternlogd  xmmA, xmmA, xmmA, 0b01010101 # "xmmA = !xmmA"
  // This is rather silly, since those could be the one instruction
  //     vpternlogd  xmmA, xmmA, xmmB, 0b00010001 # "xmmA = ~(xmmA | xmmB)"
  // There's also a pointless mov somewhere in there...
  whole_dvmask possible = ~_mm512_reduce_or_epi32((__m512i)*impossible);
#else
  // If you want something done right, do it yourself!
  // (Maybe one day this block can be removed.)
  whole_dvmask
    half    __attribute__((vector_size(32))) = (typeof(half))_mm256_or_epi32(
      _mm512_extracti32x8_epi32((__m512i)*impossible, 0)
    , _mm512_extracti32x8_epi32((__m512i)*impossible, 1)),
    quarter __attribute__((vector_size(16))) = (typeof(quarter))_mm_or_epi32(
      _mm256_extracti32x4_epi32((__m256i)half, 0)
    , _mm256_extracti32x4_epi32((__m256i)half, 1)),
  // Keep going in the vector unit instead of extracting to GPR (expensive).
    eighths __attribute__((vector_size(16))) = (typeof(eighths))_mm_or_epi32(
      (__m128i)quarter
    , _mm_shuffle_epi32(
        (__m128i)quarter
      , 0b01'00'11'10 /* [1, 0, 3, 2] "swap upper u64 with lower u64" */)),
    up16th __attribute__((vector_size(16))) = (typeof(up16th))_mm_shuffle_epi32(
      (__m128i)eighths
    , 0b01'01'01'01 /* [1, 1, 1, 1] "broadcast upper u32 of lower u64" */),
  // Final reduction of impossible and "possible = ~impossible;", at once.
    possible =
      _mm_ternarylogic_epi32(
        _mm_undefined_si128(), (__m128i)eighths, (__m128i)up16th
      , ~(_MM_TERNLOG_B | _MM_TERNLOG_C))
    [0];
#endif
  memcpy(out, &possible, PROTECTED(dvmask_bytes)());
}
EXPORT_PROTECTED(ubc_check_avx512);
RESET_FEATURES

# if !ALWAYS_AVX512
static typeof(PROTECTED(ubc_check)) *pick_ubc_check_impl
[[gnu::no_sanitize("all")]]() {
  typeof(PROTECTED(ubc_check)) *impl = PROTECTED(ubc_check_baseline);
#   define CHECK_FEATURE_AND(f) __builtin_cpu_supports(f) &&
  __builtin_cpu_init();
  if(USED_AVX512_FEATURES(CHECK_FEATURE_AND) true)
    impl = PROTECTED(ubc_check_avx512);
  return impl;
}
# endif
#endif

// TODO: non-ifunc dispatch, for non-GNU/ELF
#if ENABLE_AVX512 && !ALWAYS_AVX512
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
