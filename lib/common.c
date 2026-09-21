// © 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
// © 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>
// SPDX-License-Identifier: MIT
//
// License text available in accompanying file LICENSE.txt, or at
// https://opensource.org/licenses/MIT.
#include <stdcountof.h>
#include <string.h>

#include "bits.h"
#include "core_private.h"

#include "sha1.h"

#ifndef DO_SAFE_HASH_DEFAULT
#define DO_SAFE_HASH_DEFAULT 1
#endif

void sha1dc_init(struct sha1dc_ctx *ctx) {
  ctx->cv[0] = 0x67452301;
  ctx->cv[1] = 0xEFCDAB89;
  ctx->cv[2] = 0x98BADCFE;
  ctx->cv[3] = 0x10325476;
  ctx->cv[4] = 0xC3D2E1F0;
  ctx->bytes = 0;
  ctx->found_collision = false;
  ctx->do_safe_hash = DO_SAFE_HASH_DEFAULT;
  ctx->ubc_check = true;
  ctx->detect_coll = true;
  ctx->reduced_round_coll = false;
  ctx->collision = nullptr;
}

void sha1dc_set_do_safe_hash(struct sha1dc_ctx *ctx, bool do_safe_hash) {
  ctx->do_safe_hash = do_safe_hash;
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
  unsigned char output[static sizeof(sha1_chaining_value)]
, struct sha1dc_ctx *restrict ctx) {
  uint64_t bits = 8 * ctx->bytes;
  uint8_t  padding_size =
    ( ctx->bytes + 1 + sizeof bits + sizeof ctx->buffer - 1
                                  & -sizeof ctx->buffer)
    - ctx->bytes     - sizeof bits;
  sha1dc_ingest(ctx, sha1_padding, padding_size);

  alignas(alignof bits) unsigned char bits_bytes[sizeof bits];
  sha1_store8_aligned_beu64(bits, bits_bytes);
  sha1dc_ingest(ctx, bits_bytes, sizeof bits_bytes);
  if(ctx->bytes % sizeof ctx->buffer) unreachable();

  for(size_t i = 0; i < countof ctx->cv; i++)
    sha1_store8_beu32(ctx->cv[i], output + sizeof *ctx->cv * i);
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
