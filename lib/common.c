/***
* Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow (danshu@microsoft.com)
* Distributed under the MIT Software License.
* See accompanying file LICENSE.txt or copy at
* https://opensource.org/licenses/MIT
***/

#include <stdcountof.h>
#include <string.h>

#include "bits.h"
#include "core_private.h"

#include "sha1.h"

#ifndef SHA1DC_INIT_SAFE_HASH_DEFAULT
#define SHA1DC_INIT_SAFE_HASH_DEFAULT 1
#endif

void sha1dc_init(struct sha1dc_ctx *ctx) {
  ctx->ihv[0] = 0x67452301;
  ctx->ihv[1] = 0xEFCDAB89;
  ctx->ihv[2] = 0x98BADCFE;
  ctx->ihv[3] = 0x10325476;
  ctx->ihv[4] = 0xC3D2E1F0;
  ctx->bytes = 0;
  ctx->found_collision = false;
  ctx->safe_hash = SHA1DC_INIT_SAFE_HASH_DEFAULT;
  ctx->ubc_check = true;
  ctx->detect_coll = true;
  ctx->reduced_round_coll = false;
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
, sha1dc_collision_handler *collision, void *closure) {
  ctx->collision = collision;
  ctx->collision_closure = closure;
}

static const unsigned char sha1_padding[64] = {0b1000'0000};
bool sha1dc_finish(
  unsigned char output[static 20]
, struct sha1dc_ctx *restrict ctx) {
  uint64_t bits = 8 * ctx->bytes;
  // Padding + uint64_t bit count must take us to a whole number of blocks
  uint32_t last = ctx->bytes & 63;
  uint32_t padn = last < 56 ? 56 - last : 120 - last;
  sha1dc_ingest(ctx, sha1_padding, padn);
  // NB: ctx->buffer holds exactly 56 bytes at this point

  sha1_store8_aligned_beu64(bits, (unsigned char*)(ctx->buffer + 14));
  PROTECTED(process)(ctx, ctx->buffer);

  for(size_t i = 0; i < countof ctx->ihv; i++)
    sha1_store8_beu32(ctx->ihv[i], output + sizeof(uint32_t) * i);
  return ctx->found_collision;
}

void sha1dc_ingest(
  size_t n;
  struct sha1dc_ctx *restrict ctx
, const unsigned char buf[static n], size_t n) {
  if(!n) return;

  unsigned char held = ctx->bytes % sizeof ctx->buffer;
  unsigned char need = sizeof ctx->buffer - held;

  if(held && n >= need) {
    ctx->bytes += need;
    memcpy((char*)ctx->buffer + held, buf, need);
    PROTECTED(process)(ctx, ctx->buffer);
    buf        += need;
    n          -= need;
    held        = 0;
  }
  while(n >= sizeof ctx->buffer) {
    ctx->bytes += sizeof ctx->buffer;

#if ALLOW_UNALIGNED_ACCESS
    PROTECTED(process)(ctx, (const uint32_t UNALIGN*)buf);
#else
    memcpy(ctx->buffer, buf, sizeof ctx->buffer);
    PROTECTED(process)(ctx, ctx->buffer);
#endif
    buf += sizeof ctx->buffer;
    n   -= sizeof ctx->buffer;
  }
  if(n > 0) {
    ctx->bytes += n;
    memcpy((char*)ctx->buffer + held, buf, n);
  }
}
