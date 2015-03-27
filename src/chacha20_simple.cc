/*
Copyright (C) 2014 insane coder (http://insanecoding.blogspot.com/, http://chacha20.insanecoding.org/)

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

This implementation is intended to be simple, many optimizations can be performed.
*/


#include "chacha20_simple.h"
const char *constants = "expand 32-byte k";
void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, size_t length, const uint8_t *nonce)
{
  ctx->a[0] = LE(constants + 0);
  ctx->a[1] = LE(constants + 4);
  ctx->a[2] = LE(constants + 8);
  ctx->a[3] = LE(constants + 12);

  ctx->b[0] = LE(key + 0);
  ctx->b[1] = LE(key + 4);
  ctx->b[2] = LE(key + 8);
  ctx->b[3] = LE(key + 12);

  ctx->c[0] = LE(key + 16 % length);
  ctx->c[1] = LE(key + 20 % length);
  ctx->c[2] = LE(key + 24 % length);
  ctx->c[3] = LE(key + 28 % length);

  //Surprise! This is really a block cipher in CTR mode
  ctx->d[0] = 0; //Counter
  ctx->d[1] = LE(nonce+0);
  ctx->d[2] = LE(nonce+4);
  ctx->d[3] = LE(nonce+8);

  ctx->available = 0;
}

#define QUARTERROUND(a, b, c, d) \
    a += b; d = ROTL32(d ^ a, 16); \
    c += d; b = ROTL32(b ^ c, 12); \
    a += b; d = ROTL32(d ^ a, 8); \
    c += d; b = ROTL32(b ^ c, 7);

static inline bool chacha20_block(chacha20_ctx *ctx, uint32_t output[16])
{
  int i = 10;
  int j;
  uint32_t *a = output;
  uint32_t *b = output + 4;
  uint32_t *c = output + 8;
  uint32_t *d = output + 12;
  memcpy(a, ctx->a, sizeof(ctx->a));
  memcpy(b, ctx->b, sizeof(ctx->b));
  memcpy(c, ctx->c, sizeof(ctx->c));
  memcpy(d, ctx->d, sizeof(ctx->d));
  while (i--)
  {
    for (j = 0; j < 4; ++j)
    {
      QUARTERROUND(a[j], b[j], c[j], d[j])
    }
    for (j = 0; j < 4; ++j)
    {
      QUARTERROUND(a[j], b[(j + 1) % 4], c[(j + 2) % 4], d[(j + 3) % 4])
    }
  }
  for (i = 0; i < 4; ++i)
  {
    uint32_t result = a[i] + ctx->a[i];
    FROMLE((uint8_t *)(a+i), result);
  }
  for (i = 0; i < 4; ++i)
  {
    uint32_t result = b[i] + ctx->b[i];
    FROMLE((uint8_t *)(b+i), result);
  }
  for (i = 0; i < 4; ++i)
  {
    uint32_t result = c[i] + ctx->c[i];
    FROMLE((uint8_t *)(c+i), result);
  }
  for (i = 0; i < 4; ++i)
  {
    uint32_t result = d[i] + ctx->d[i];
    FROMLE((uint8_t *)(d+i), result);
  }

  /*
  Official specs calls for performing a 64 bit increment here, and limit usage to 2^64 blocks.
  However, recommendations for CTR mode in various papers recommend including the nonce component for a 128 bit increment.
  This implementation will remain compatible with the official up to 2^64 blocks, and past that point, the official is not intended to be used.
  This implementation with this change also allows this algorithm to become compatible for a Fortuna-like construct.
  */
  if (!++ ctx->d[0]) { return false; }
  return true;
}

static inline void chacha20_xor(uint8_t *keystream, const uint8_t **in, uint8_t **out, size_t length)
{
  uint8_t *end_keystream = keystream + length;
  do { *(*out)++ = *(*in)++ ^ *keystream++; } while (keystream < end_keystream);
}

bool chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length)
{
  if (length)
  {
    uint8_t *const k = (uint8_t *)ctx->keystream;

    //First, use any buffered keystream from previous calls
    if (ctx->available)
    {
      size_t amount = MIN(length, ctx->available);
      chacha20_xor(k + (sizeof(ctx->keystream)-ctx->available), &in, &out, amount);
      ctx->available -= amount;
      length -= amount;
    }

    //Then, handle new blocks
    while (length)
    {
      size_t amount = MIN(length, sizeof(ctx->keystream));
      if (!chacha20_block(ctx, ctx->keystream)){
        return false;
      }
      chacha20_xor(k, &in, &out, amount);
      length -= amount;
      ctx->available = sizeof(ctx->keystream) - amount;
    }
  }
  return true;
}
