#pragma once
#include <stdint.h>
#include <stdbit.h>

#ifndef ALLOW_UNALIGNED_ACCESS
# if  defined __amd64__     || defined __amd64                       \
   || defined __x86_64__    || defined __x86_64                      \
   || defined i386          || defined __i386   || defined __i386__  \
   || defined __i486__      || defined __i586__ || defined __i686__  \
   || defined _M_IX86       || defined __X86__  || defined _X86_     \
   || defined __THW_INTEL__ || defined __I86__  || defined __INTEL__ \
   || defined __386         || defined _M_X64   || defined _M_AMD64
#   define ALLOW_UNALIGNED_ACCESS 1
# else
#   define ALLOW_UNALIGNED_ACCESS 0
# endif
#endif

#if ALLOW_UNALIGNED_ACCESS
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
// GCC needs explicit unroll pragmas on all these loops. (!!??)
static inline uint32_t sha1_load8_beu32(const unsigned char p[static 4]) {
  uint32_t x = 0;
#pragma GCC unroll 999
  for(char i = 32; (i -= 8) + 8;) x |= (uint32_t)*p++ << i;
  return x;
}
static inline void sha1_store8_beu64(uint64_t x, unsigned char p[static 8]) {
#pragma GCC unroll 999
  for(char i = 64; (i -= 8) + 8;) *p++ = x >> i;
}
static inline void sha1_store8_beu32(uint32_t x, unsigned char p[static 4]) {
#pragma GCC unroll 999
  for(char i = 32; (i -= 8) + 8;) *p++ = x >> i;
}
#endif
