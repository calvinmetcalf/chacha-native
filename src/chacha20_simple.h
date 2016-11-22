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
*/

#ifndef CHACHA20_SIMPLE_H
#define CHACHA20_SIMPLE_H
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define INTRINSIC \
static inline __attribute__((__gnu_inline__, __always_inline__))
#define add _mm_add_epi32
#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#define FROMLE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifdef __cplusplus
extern "C"
{
#endif

// SSE2 stuff based on https://github.com/bitwiseshiftleft/crandom/
#ifdef __SSE2__
  #define SSE2 1
  #define CONV 0
  #include <emmintrin.h>
# else
  #define SSE2 0
  #define CONV 1
# endif
#ifdef __SSE3__
  #define SSE3 1
  #include <tmmintrin.h>
# else
  #define SSE3 0
# endif
#ifdef __XOP__
  INTRINSIC ssereg xop_rotate(int amount, ssereg x) {
    ssereg out;
    asm ("vprotd %1, %2, %0" : "=x"(out) : "x"(x), "g"(amount));
    return out;
  }
  #define XOP 1
# else
  #define XOP 0
# endif
#define SSE (SSE2 || SSE3)

# if CONV
  static inline uint32_t ROTL32(uint32_t v, uint32_t n) {
    return ((v) << (n)) | ((v) >> (32 - (n)));
  }
  #define QUARTERROUND(a, b, c, d) \
      a += b; d = ROTL32(d ^ a, 16); \
      c += d; b = ROTL32(b ^ c, 12); \
      a += b; d = ROTL32(d ^ a, 8); \
      c += d; b = ROTL32(b ^ c, 7);
#endif

#if SSE
  INTRINSIC __m128i sse2_rotate(__m128i a, int r) {
   return _mm_slli_epi32(a, r) ^ _mm_srli_epi32(a, 32-r);
  }
  #define shuffle(x,i) _mm_shuffle_epi32(x, \
  i + ((i+1)&3)*4 + ((i+2)&3)*16 + ((i+3)&3)*64)

  #define SHUFFLE(b, c, d)\
    b = shuffle(b, 1);\
    c = shuffle(c, 2);\
    d = shuffle(d, 3);
#endif

# if SSE3
  static const __m128i shuffle8  = { 0x0605040702010003ull, 0x0E0D0C0F0A09080Bull };
  static const __m128i shuffle16 = { 0x0504070601000302ull, 0x0D0C0F0E09080B0Aull };

  static inline void
  round(__m128i *a, __m128i *b, __m128i *c, __m128i *d) {
    *a = add(*a,*b); *d = _mm_shuffle_epi8(*d ^ *a, shuffle16);
    *c = add(*c,*d); *b = sse2_rotate(*b ^ *c, 12);
    *a = add(*a,*b); *d = _mm_shuffle_epi8( *d ^ *a, shuffle8);
    *c = add(*c,*d); *b = sse2_rotate(*b ^ *c, 7);
  }
# else
  #if SSE2
    #if XOP
    static inline void
     round(__m128i *a, __m128i *b, __m128i *c, __m128i *d) {
       *a = add(*a,*b); *d = xop_rotate(*d ^ *a, 16);
       *c = add(*c,*d); *b = xop_rotate(*b ^ *c, 12);
       *a = add(*a,*b); *d = xop_rotate(*d ^ *a, 8);
       *c = add(*c,*d); *b = xop_rotate(*b ^ *c, 7);
    # else
      static inline void
       round(__m128i *a, __m128i *b, __m128i *c, __m128i *d) {
         *a = add(*a,*b); *d = sse2_rotate(*d ^ *a, 16);
         *c = add(*c,*d); *b = sse2_rotate(*b ^ *c, 12);
         *a = add(*a,*b); *d = sse2_rotate(*d ^ *a, 8);
         *c = add(*c,*d); *b = sse2_rotate(*b ^ *c, 7);
      }
    #endif
  #endif
#endif
typedef struct
{
  uint32_t key1[4] __attribute__ ((aligned (16))) ;
  uint32_t key2[4] __attribute__ ((aligned (16))) ;
  uint32_t nonce[4] __attribute__ ((aligned (16))) ;
  uint32_t keystream[16];
  size_t available;
} chacha20_ctx;

//Call this to initilize a chacha20_ctx, must be called before all other functions
void chacha20_setup(chacha20_ctx *ctx, const uint8_t *key, size_t length, const uint8_t *nonce);

//Raw keystream for the current block, convert output to uint8_t[] for individual bytes. Counter is incremented upon use
bool chacha20_block(chacha20_ctx *ctx, uint32_t output[16]);

//Encrypt an arbitrary amount of plaintext, call continuously as needed
bool chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *in, uint8_t *out, size_t length);

#ifdef __cplusplus
}
#endif

#endif
