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

void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, size_t length, const uint8_t *nonce)
{

  ctx->key1[0] = LE(key + 0);
  ctx->key1[1] = LE(key + 4);
  ctx->key1[2] = LE(key + 8);
  ctx->key1[3] = LE(key + 12);

  ctx->key2[0] = LE(key + 16 % length);
  ctx->key2[1] = LE(key + 20 % length);
  ctx->key2[2] = LE(key + 24 % length);
  ctx->key2[3] = LE(key + 28 % length);
  //Surprise! This is really a block cipher in CTR mode
  ctx->nonce[0] = 0; //Counter
  ctx->nonce[1] = LE(nonce+0);
  ctx->nonce[2] = LE(nonce+4);
  ctx->nonce[3] = LE(nonce+8);

  ctx->available = 0;
}

# if CONV
uint32_t const constants[4] __attribute__ ((aligned (16))) = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
bool chacha20_block(chacha20_ctx *ctx, uint32_t output[16])
{
  uint32_t *const nonce = ctx->nonce;
  int i = 10;

  memcpy(output, constants, sizeof(constants));
  memcpy(output + 4, ctx->key1, sizeof(ctx->key1));
  memcpy(output + 8, ctx->key2, sizeof(ctx->key2));
  memcpy(output + 12, ctx->nonce, sizeof(ctx->nonce));
  while (i--)
  {
    QUARTERROUND(output[0], output[4], output[8], output[12])
    QUARTERROUND(output[1], output[5], output[9], output[13])
    QUARTERROUND(output[2], output[6], output[10], output[14])
    QUARTERROUND(output[3], output[7], output[11], output[15])

    QUARTERROUND(output[0], output[5], output[10], output[15])
    QUARTERROUND(output[1], output[6], output[11], output[12])
    QUARTERROUND(output[2], output[7], output[8], output[13])
    QUARTERROUND(output[3], output[4], output[9], output[14])
  }
  i = 0;
  while (i < 4)
  {
    uint32_t result = output[i] + constants[i];
    FROMLE((uint8_t *)(output+i), result);
    i++;
  }

  while (i < 8)
  {
    uint32_t result = output[i] + ctx->key1[i % 4];
    FROMLE((uint8_t *)(output+i), result);
    i++;
  }

  while (i < 12)
  {
    uint32_t result = output[i] + ctx->key2[i % 4];
    FROMLE((uint8_t *)(output+i), result);
    i++;
  }

  while (i < 16)
  {
    uint32_t result = output[i] + ctx->nonce[i % 4];
    FROMLE((uint8_t *)(output+i), result);
    i++;
  }
  /*
  Official specs calls for performing a 64 bit increment here, and limit usage to 2^64 blocks.
  However, recommendations for CTR mode in various papers recommend including the nonce component for a 128 bit increment.
  This implementation will remain compatible with the official up to 2^64 blocks, and past that point, the official is not intended to be used.
  This implementation with this change also allows this algorithm to become compatible for a Fortuna-like construct.
  */
  if (!++nonce[0]) { return false; }
  return true;
}
# endif

#if SSE
bool chacha20_block(chacha20_ctx *ctx, uint32_t output[16])
{
  uint32_t *const nonce = ctx->nonce;
  int i = 10;
  __m128i a = {0x3320646e61707865ull, 0x6b20657479622d32ull};
  __m128i b = {};
  __m128i c = {};
  __m128i d = {};
  memcpy(&b, ctx->key1, sizeof(ctx->key1));
  memcpy(&c, ctx->key2, sizeof(ctx->key2));
  memcpy(&d, ctx->nonce, sizeof(ctx->nonce));

  __m128i ap = a;
  __m128i bp = b;
  __m128i cp = c;
  __m128i dp = d;
  while (i--)
  {
    round(&a, &b, &c, &d);
    SHUFFLE(b, c, d)

    round(&a, &b, &c, &d);
    SHUFFLE(d, c, b)
  }
  i = 0;
  ap = _mm_add_epi32(a, ap);
  uint32_t *ar = (uint32_t *) &ap;
  bp = _mm_add_epi32(b, bp);
  uint32_t *br = (uint32_t *) &bp;
  cp = _mm_add_epi32(c, cp);
  uint32_t *cr = (uint32_t *) &cp;
  dp = _mm_add_epi32(d, dp);
  uint32_t *dr = (uint32_t *) &dp;
  while (i < 4)
  {
    FROMLE((uint8_t *)(output+i), ar[i]);
    i++;
  }
  while (i < 8)
  {
    FROMLE((uint8_t *)(output+i), br[i % 4]);
    i++;
  }
  while (i < 12)
  {
    FROMLE((uint8_t *)(output+i), cr[i % 4]);
    i++;
  }
  while (i < 16)
  {
    FROMLE((uint8_t *)(output+i), dr[i % 4]);
    i++;
  }
  if (!++nonce[0]) { return false; }
  return true;
}
#endif
static inline void chacha20_xor(uint8_t *keystream, const uint8_t **in, uint8_t **out, size_t length)
{
  #pragma clang loop interleave(enable)
  for (size_t i = 0; i < length; i++) {
     *(*out + i) = *(*in + i) ^ *(keystream + i);
  }
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
      in += amount;
      out += amount;
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
      in += amount;
      out += amount;
    }
  }
  return true;
}
