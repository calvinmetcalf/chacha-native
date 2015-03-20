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

#include "chacha20_complex.h"
const char *constants = "expand 32-byte k";



#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;

#define QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = ROTL32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = ROTL32(x[b] ^ x[c], 7);

#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#define ROUND(a, b, c, d) {\
    a = a + b;\
    d = ROTL32(d ^ a , 16); \
    c = c + d;\
    b = ROTL32(b ^ c, 12); \
    a = a + b;\
    d = ROTL32(d ^ a , 8); \
    c = c + d;\
    b = ROTL32(b ^ c, 7);\
  }

#define TOARRAY(a, b, c, d, x) \
    x[0] = a[0];x[1] = a[1];x[2] = a[2];x[3] = a[3];\
    x[4] = b[0];x[5] = b[1];x[6] = b[2];x[7] = b[3];\
    x[8] = c[0];x[9] = c[1];x[10] = c[2];x[11] = c[3];\
    x[12] = d[0];x[13] = d[1];x[14] = d[2];x[15] = d[3];

void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, size_t length, const uint8_t *nonce)
{
  ctx->a = uint32x4(
    LE(constants + 0),
    LE(constants + 4),
    LE(constants + 8),
    LE(constants + 12)
  );
  ctx->b = uint32x4(
    LE(key + 0),
    LE(key + 4),
    LE(key + 8),
    LE(key + 12)
  );
  ctx->c = uint32x4(
    LE(key + 16 % length),
    LE(key + 20 % length),
    LE(key + 24 % length),
    LE(key + 28 % length)
  );
  ctx->d = uint32x4(
    0,
    LE(nonce + 0),
    LE(nonce + 4),
    LE(nonce + 8)
  );

  ctx->available = 0;
}

bool chacha20_block(chacha20_ctx *ctx, uint32_t output[16])
{
  int i = 10;

  uint32x4 a = ctx->a;
  uint32x4 b = ctx->b;
  uint32x4 c = ctx->c;
  uint32x4 d = ctx->d;

  while (i--)
  {
    ROUND(a, b, c, d);
    b = svec_rotate(b, 1);
    c = svec_rotate(c, 2);
    d = svec_rotate(d, 3);
    ROUND(a, b, c, d);
    b = svec_rotate(b, 3);
    c = svec_rotate(c, 2);
    d = svec_rotate(d, 1);
  }
  a = a + ctx->a;
  b = b + ctx->b;
  c = c + ctx->c;
  d = d + ctx->d;
  a.store((uint32x4*)(output + 0));
  b.store((uint32x4*)(output + 4));
  c.store((uint32x4*)(output + 8));
  d.store((uint32x4*)(output + 12));
  for (i = 0; i < 16; ++i)
  {
    uint32_t result = output[i];
    FROMLE((uint8_t *)(output+i), result);
  }

  // limit it to single counter
  if (!++ctx->d[0])
    return false;

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
