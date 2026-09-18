#pragma once

#ifndef ENABLE_X86_EXTENSIONS
  // Similar to but different from the check in sha1.c
# if defined __amd64__ || defined __amd64 || defined __x86_64__ || \
     defined __x86_64  || defined _M_X64  || defined _M_AMD64
#   define ENABLE_X86_EXTENSIONS 1
# endif
#endif
#if ENABLE_X86_EXTENSIONS

#include <stdint.h>
#include <immintrin.h>

// Nice way to enable processor features for delimited regions of code.
#define PRAGMA_WORDS(...)            _Pragma(# __VA_ARGS__)
#define FEATURE_INTO_TARGET(feature) feature ","
#define SET_FEATURES(F) \
   _Pragma("GCC push_options") \
   STRICT1(PRAGMA_WORDS, GCC target F(FEATURE_INTO_TARGET))
#define RESET_FEATURES  _Pragma("GCC pop_options")

# define U(M)    uint ## M ## _t
# define V(N, M) U(M) [[gnu::vector_size(N * sizeof(U(M)))]]
typedef V(64,  8) v64u8;
typedef V(16, 32) v16u32;
typedef V( 8, 32) v8u32;
typedef V( 4, 32) v4u32;
# undef V
# undef U
typedef __mmask64 v64s1;
typedef __mmask16 v16s1;

// Format given inline-asm named operands for use in an x86 assembly template.
#define AVX512_ARGS2(dst, src) \
  "\t" /* go from opcode mnemonic column to operands */ \
  "{"  /* AT&T dialect */                               \
    "%[" # src "], "                                    \
    "%[" # dst "]"                                      \
  "|"  /* Intel dialect */                              \
    "%[" # dst "], "                                    \
    "%[" # src "]"                                      \
  "}"
#define AVX512_ARGS2I(dst, src, imm) "\t" \
  "{$"  # imm  ", %[" # src "], %[" # dst "]"  \
  "|%[" # dst "], %[" # src "], "   # imm  "}"
#define AVX512_ARGS3(dst, src1, src2) "\t" \
  "{%[" # src2 "], %[" # src1 "], %[" # dst  "]"  \
  "|%[" # dst  "], %[" # src1 "], %[" # src2 "]}"
#define AVX512_ARGS3K(dst, k, src1, src2) "\t" \
  "{%[" # src2 "], %[" # src1 "], %[" # dst  "]%{%[" # k "]%}"  \
  "|%[" # dst  "]%{%[" # k "]%}, %[" # src1 "], %[" # src2 "]}"

// -flax-vector-conversions would remove the need for these wrappers, but it
// would also remove the typechecking that comes from using GCC's vector types.
// So we'll just do things by hand.
#define INTRINSIC(D, tgt, ...) \
  static inline D                                                      \
    [[gnu::always_inline, gnu::target(tgt) __VA_OPT__(,) __VA_ARGS__]]
#define WRAPPER(D, tgt, ...)   INTRINSIC( \
    D                                              \
  , tgt, gnu::artificial __VA_OPT__(,) __VA_ARGS__)
WRAPPER(v64u8 loadu_v64u8, "avx512bw")(const void *p) {
  return (v64u8)_mm512_loadu_epi8(p);
}
WRAPPER(v16u32 loadu_v16u32, "avx512f")(const void *p) {
  return (v16u32)_mm512_loadu_epi32(p);
}
WRAPPER(v16u32 load_zv16u32, "avx512f")(v64s1 k, const v16u32 *p) {
  return (v16u32)_mm512_maskz_load_epi32(k, p);
}
WRAPPER(v64u8 index2_v64u8, "avx512vbmi")(v64u8 lo, v64u8 hi, v64u8 i) {
  return (v64u8)_mm512_permutex2var_epi8((__m512i)lo, (__m512i)i, (__m512i)hi);
}
WRAPPER(v64s1 test_v64u8, "avx512bw")(v64u8 x, v64u8 y) {
  return _mm512_test_epi8_mask((__m512i)x, (__m512i)y);
}
WRAPPER(v64u8 shuffle_v64u8, "avx512bw")(v64u8 x, v64u8 i) {
  return (v64u8)_mm512_shuffle_epi8((__m512i)x, (__m512i)i);
}
struct s2v8u32 { v8u32 lo, hi; };
WRAPPER(struct s2v8u32 halves_v16u32, "avx512f")(v16u32 x) {
  // It is necessary to compute `hi` before "computing" `lo`, and it is also
  // necessary to avoid simplifying to a compound literal. Otherwise, GCC will
  // do something ridiculuous in callers:
  //     vmovdqa64      xmmB, xmmA
  //     vextracti64x4  xmmA, xmmA, 1
  //     # ... use xmmA as hi and xmmB as lo
  // The correct code is
  //     vextracti64x4  xmmB, xmmA, 1
  //     # ... use xmmA as lo and xmmB as hi
  struct s2v8u32 ret;
  ret.hi = (v8u32)_mm512_extracti64x4_epi64((__m512i)x, 1);
  ret.lo = (v8u32)_mm512_castsi512_si256((__m512i)x);
  return ret;
}
WRAPPER(v8u32 or_v8u32, "avx2")(v8u32 x, v8u32 y) {
  return (v8u32)_mm256_or_si256((__m256i)x, (__m256i)y);
}
struct s2v4u32 { v4u32 lo, hi; };
WRAPPER(struct s2v4u32 halves_v8u32, "avx2")(v8u32 x) {
  struct s2v4u32 ret;
  ret.hi = (v4u32)_mm256_extracti128_si256((__m256i)x, 1);
  ret.lo = (v4u32)_mm256_castsi256_si128((__m256i)x);
  return ret;
}
WRAPPER(v4u32 shuffle_v4u32, "sse2")(v4u32 x, uint8_t i) {
  return (v4u32)_mm_shuffle_epi32((__m128i)x, i);
}
WRAPPER(v4u32 or_v4u32, "sse2")(v4u32 x, v4u32 y) {
  return (v4u32)_mm_or_si128((__m128i)x, (__m128i)y);
}
WRAPPER(v4u32 xor_v4u32, "sse2")(v4u32 x, v4u32 y) {
  return (v4u32)_mm_xor_si128((__m128i)x, (__m128i)y);
}
INTRINSIC(v4u32 nor_v4u32, "avx512vl")(v4u32 x, v4u32 y) {
  // _mm256_ternarylogic_epi32 subsumes, but requires only F
  return (v4u32)_mm_ternarylogic_epi32(
    _mm_undefined_si128(), (__m128i)x, (__m128i)y
  , ~(_MM_TERNLOG_B | _MM_TERNLOG_C));
}

WRAPPER(v4u32 sha1msg1, "sha")(v4u32 Wrn16_n13, v4u32 Wrn12_n9) {
  return (v4u32)_mm_sha1msg1_epu32((__m128i)Wrn16_n13, (__m128i)Wrn12_n9);
}
WRAPPER(v4u32 sha1msg2, "sha")(v4u32 Wrp0_p3, v4u32 Wrn4_n1) {
  return (v4u32)_mm_sha1msg2_epu32((__m128i)Wrp0_p3, (__m128i)Wrn4_n1);
}
WRAPPER(v4u32 sha1nexte, "sha")(v4u32 old_abcd, v4u32 Wrp0_p3) {
  return (v4u32)_mm_sha1nexte_epu32((__m128i)old_abcd, (__m128i)Wrp0_p3);
}
WRAPPER(v4u32 sha1rnds4, "sha")(v4u32 abcd, v4u32 Wrp0e_p3, int8_t fk) {
  return (v4u32)_mm_sha1rnds4_epu32((__m128i)abcd, (__m128i)Wrp0e_p3, fk);
}

// GCC doesn't seem to understand that it can make the dst and src1 operands of
// an AVX-512 instruction generated from an intrinisic the same. This causes it
// to sprinkle useless movs to copy src1 into dst (even though the remaining
// copy of the old value is never used again). But it does understand how to get
// things right for an inline asm statement. Go figure.
// "OR mask vector 16 uint32_t memory"
WRAPPER(v16u32 or_mv16u32_mem, "avx512f")(
  v16u32 dst, v16s1 k, v16u32 src1, const v16u32 *src2) {
  asm(
    "vpord" AVX512_ARGS3K(dst, k, src1, src2)
  : [dst]"+v"(dst)
  : [k]"Yk"(k), [src1]"v"(src1), [src2]"m"(*src2));
  return dst;
}

// "NOR reduce ..."
INTRINSIC(uint32_t nor_rv16u32, "avx512dq,avx512vl")(v16u32 x) {
#if !__OPTIMIZE__
  // At the end of this, GCC seems to want to do something like
  //     vpord       xmmA, xmmB, xmmA             # fold up last two u32
  //     vpternlogd  xmmA, xmmA, xmmA, 0b01010101 # "xmmA = ~xmmA"
  // This is rather silly, since those could be the one instruction
  //     vpternlogd  xmmA, xmmA, xmmB, 0b00010001 # "xmmA = ~(xmmA | xmmB)"
  // There's also a pointless mov somewhere in there...
  return ~_mm512_reduce_or_epi32((__m512i)x);
#else
  // If you want something done right, do it yourself!
  struct s2v8u32 halves   = halves_v16u32(x);
  v8u32          half     = or_v8u32(halves.lo,   halves.hi);
  struct s2v4u32 quarters = halves_v8u32(half);
  v4u32          quarter  = or_v4u32(quarters.lo, quarters.hi);
  // Keep going in the vector unit instead of extracting to GPR (expensive).
  constexpr uint8_t v4u32_as_v2u64_swap    = 0b01'00'11'10;
  v4u32 eighths = or_v4u32(quarter, shuffle_v4u32(quarter, v4u32_as_v2u64_swap));
  constexpr uint8_t v4u32_as_v2v2u32_swaps = 0b10'11'00'01;
  v4u32 sxtnths =
    nor_v4u32(eighths, shuffle_v4u32(eighths, v4u32_as_v2v2u32_swaps));
  return sxtnths[0];
#endif
}

#undef WRAPPER
#endif
