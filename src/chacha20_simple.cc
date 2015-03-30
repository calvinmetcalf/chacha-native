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

#define constants "expand 32-byte k"

void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, size_t length, const uint8_t *nonce)
{

  ctx->a[0] = LE(constants);
  ctx->a[1] = LE(constants + 4);
  ctx->a[2] = LE(constants + 8);
  ctx->a[3] = LE(constants + 12);

  ctx->b[0] = LE(key);
  ctx->b[1] = LE(key + 4);
  ctx->b[2] = LE(key + 8);
  ctx->b[3] = LE(key + 12);

  ctx->c[0] = LE(key + 16);
  ctx->c[1] = LE(key + 20);
  ctx->c[2] = LE(key + 24);
  ctx->c[3] = LE(key + 28);

  //Surprise! This is really a block cipher in CTR mode
  ctx->d0 = 0; //Counter
  ctx->d1 = LE(nonce+0);
  ctx->d2 = LE(nonce+4);
  ctx->d3 = LE(nonce+8);

  ctx->available = 0;
}

#define QUARTERROUND(a, b, c, d) \
    a += b; d = ROTL32(d ^ a, 16); \
    c += d; b = ROTL32(b ^ c, 12); \
    a += b; d = ROTL32(d ^ a, 8); \
    c += d; b = ROTL32(b ^ c, 7);
#define TWOX(a) \
    do{a}while(0);\
    do{a}while(0);

#define FIVEX(a) \
    a\
    a\
    a\
    a\
    a;

#define TENX(a) FIVEX(TWOX(a));

static inline void chacha20_block(chacha20_ctx *ctx, uint32_t output[16], uint32_t counter)
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
  d[0] = counter;
  d[1] = ctx->d1;
  d[2] = ctx->d2;
  d[3] = ctx->d3;
  TENX(
    for (j = 0; j < 4; ++j)
    {
      QUARTERROUND(a[j], b[j], c[j], d[j])
    }
    for (j = 0; j < 4; ++j)
    {
      QUARTERROUND(a[j], b[(j + 1) % 4], c[(j + 2) % 4], d[(j + 3) % 4])
    }
  )
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
  uint32_t result = d[0] + counter;
  FROMLE((uint8_t *)(d), result);

  result = d[1] + ctx->d1;
  FROMLE((uint8_t *)(d+1), result);

  result = d[2] + ctx->d2;
  FROMLE((uint8_t *)(d+2), result);

  result = d[3] + ctx->d3;
  FROMLE((uint8_t *)(d+3), result);
}

static inline void chacha20_xor(uint8_t *keystream, const uint8_t **in, uint8_t **out, size_t length)
{
  uint8_t *end_keystream = keystream + length;
  do { 
    *(*out)++ = *(*in)++ ^ *keystream++;
  } while (keystream < end_keystream);
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
    uint32_t counter = ctx->d0;
    while (length)
    {
      size_t amount = MIN(length, sizeof(ctx->keystream));
      chacha20_block(ctx, ctx->keystream, counter);
      if (!++counter) {
        return false;
      }
      chacha20_xor(k, &in, &out, amount);
      length -= amount;
      ctx->available = sizeof(ctx->keystream) - amount;
    }
    ctx->d0 = counter;
  }
  return true;
}
