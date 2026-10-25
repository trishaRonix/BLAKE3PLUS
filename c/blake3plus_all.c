/*
 * BLAKE3PLUS Amalgamated Source Distribution
 *
 * This file combines the portable core implementation of BLAKE3 and
 * BLAKE3PLUS multi-threading, cgroup detection, and memory protection
 * into a single C translation unit.
 *
 * SIMD assembly files (.S) may still be compiled alongside if desired,
 * or this file can be built with standard C flags (-O3 -pthread).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#define BLAKE3PLUS_AMALGAMATED 1


/* --- Begin: c/blake3_impl.h --- */
#ifndef BLAKE3_IMPL_H
#define BLAKE3_IMPL_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blake3.h"

#ifdef __cplusplus
extern "C" {
#endif

// internal flags
enum blake3_flags {
  CHUNK_START         = 1 << 0,
  CHUNK_END           = 1 << 1,
  PARENT              = 1 << 2,
  ROOT                = 1 << 3,
  KEYED_HASH          = 1 << 4,
  DERIVE_KEY_CONTEXT  = 1 << 5,
  DERIVE_KEY_MATERIAL = 1 << 6,
};

// This C implementation tries to support recent versions of GCC, Clang, and
// MSVC.
#if defined(_MSC_VER)
#define INLINE static __forceinline
#else
#define INLINE static inline __attribute__((always_inline))
#endif

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#if (defined(__x86_64__) || defined(_M_X64)) && !defined(_M_ARM64EC)
#define IS_X86
#define IS_X86_64
#endif

#if defined(__i386__) || defined(_M_IX86)
#define IS_X86
#define IS_X86_32
#endif

#if defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
#define IS_AARCH64
#endif

#if defined(IS_X86)
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#endif

#if !defined(BLAKE3_USE_NEON) 
  // If BLAKE3_USE_NEON not manually set, autodetect based on AArch64ness
  #if defined(IS_AARCH64)
    #if defined(__ARM_BIG_ENDIAN)
      #define BLAKE3_USE_NEON 0
    #else
      #define BLAKE3_USE_NEON 1
    #endif
  #else
    #define BLAKE3_USE_NEON 0
  #endif
#endif

#if defined(IS_X86)
#define MAX_SIMD_DEGREE 16
#elif BLAKE3_USE_NEON == 1
#define MAX_SIMD_DEGREE 4
#else
#define MAX_SIMD_DEGREE 1
#endif

// There are some places where we want a static size that's equal to the
// MAX_SIMD_DEGREE, but also at least 2.
#define MAX_SIMD_DEGREE_OR_2 (MAX_SIMD_DEGREE > 2 ? MAX_SIMD_DEGREE : 2)

static const uint32_t IV[8] = {0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL,
                               0xA54FF53AUL, 0x510E527FUL, 0x9B05688CUL,
                               0x1F83D9ABUL, 0x5BE0CD19UL};

static const uint8_t MSG_SCHEDULE[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
};

/* Find index of the highest set bit */
/* x is assumed to be nonzero.       */
static unsigned int highest_one(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return 63 ^ (unsigned int)__builtin_clzll(x);
#elif defined(_MSC_VER) && defined(IS_X86_64)
  unsigned long index;
  _BitScanReverse64(&index, x);
  return index;
#elif defined(_MSC_VER) && defined(IS_X86_32)
  if(x >> 32) {
    unsigned long index;
    _BitScanReverse(&index, (unsigned long)(x >> 32));
    return 32 + index;
  } else {
    unsigned long index;
    _BitScanReverse(&index, (unsigned long)x);
    return index;
  }
#else
  unsigned int c = 0;
  if(x & 0xffffffff00000000ULL) { x >>= 32; c += 32; }
  if(x & 0x00000000ffff0000ULL) { x >>= 16; c += 16; }
  if(x & 0x000000000000ff00ULL) { x >>=  8; c +=  8; }
  if(x & 0x00000000000000f0ULL) { x >>=  4; c +=  4; }
  if(x & 0x000000000000000cULL) { x >>=  2; c +=  2; }
  if(x & 0x0000000000000002ULL) {           c +=  1; }
  return c;
#endif
}

// Count the number of 1 bits.
INLINE unsigned int popcnt(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return (unsigned int)__builtin_popcountll(x);
#else
  unsigned int count = 0;
  while (x != 0) {
    count += 1;
    x &= x - 1;
  }
  return count;
#endif
}

// Largest power of two less than or equal to x. As a special case, returns 1
// when x is 0. 
INLINE uint64_t round_down_to_power_of_2(uint64_t x) {
  return 1ULL << highest_one(x | 1);
}

INLINE uint32_t counter_low(uint64_t counter) { return (uint32_t)counter; }

INLINE uint32_t counter_high(uint64_t counter) {
  return (uint32_t)(counter >> 32);
}

INLINE uint32_t load32(const void *src) {
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)(p[0]) << 0) | ((uint32_t)(p[1]) << 8) |
         ((uint32_t)(p[2]) << 16) | ((uint32_t)(p[3]) << 24);
}

INLINE void load_key_words(const uint8_t key[BLAKE3_KEY_LEN],
                           uint32_t key_words[8]) {
  key_words[0] = load32(&key[0 * 4]);
  key_words[1] = load32(&key[1 * 4]);
  key_words[2] = load32(&key[2 * 4]);
  key_words[3] = load32(&key[3 * 4]);
  key_words[4] = load32(&key[4 * 4]);
  key_words[5] = load32(&key[5 * 4]);
  key_words[6] = load32(&key[6 * 4]);
  key_words[7] = load32(&key[7 * 4]);
}

INLINE void load_block_words(const uint8_t block[BLAKE3_BLOCK_LEN],
                             uint32_t block_words[16]) {
  for (size_t i = 0; i < 16; i++) {
      block_words[i] = load32(&block[i * 4]);
  }
}

INLINE void store32(void *dst, uint32_t w) {
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
}

INLINE void store_cv_words(uint8_t bytes_out[32], uint32_t cv_words[8]) {
  store32(&bytes_out[0 * 4], cv_words[0]);
  store32(&bytes_out[1 * 4], cv_words[1]);
  store32(&bytes_out[2 * 4], cv_words[2]);
  store32(&bytes_out[3 * 4], cv_words[3]);
  store32(&bytes_out[4 * 4], cv_words[4]);
  store32(&bytes_out[5 * 4], cv_words[5]);
  store32(&bytes_out[6 * 4], cv_words[6]);
  store32(&bytes_out[7 * 4], cv_words[7]);
}

void blake3_compress_in_place(uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags);

void blake3_compress_xof(const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64]);

void blake3_xof_many(const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint8_t block_len, uint64_t counter, uint8_t flags,
                     uint8_t out[64], size_t outblocks);

void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t *out);

size_t blake3_simd_degree(void);

BLAKE3_PRIVATE size_t blake3_compress_subtree_wide(const uint8_t *input, size_t input_len,
                                                   const uint32_t key[8],
                                                   uint64_t chunk_counter, uint8_t flags,
                                                   uint8_t *out, bool use_tbb);

#if defined(BLAKE3_USE_TBB)
BLAKE3_PRIVATE void blake3_compress_subtree_wide_join_tbb(
    // shared params
    const uint32_t key[8], uint8_t flags, bool use_tbb,
    // left-hand side params
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    // right-hand side params
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n) NOEXCEPT;
#endif

#if defined(BLAKE3PLUS_ENABLE_PTHREAD)
BLAKE3_PRIVATE void blake3plus_compress_subtree_wide_join_pthread(
    const uint32_t key[8], uint8_t flags, bool use_mt,
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n);
#endif

// Declarations for implementation-specific functions.
void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags);

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64]);

void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t *out);

#if defined(IS_X86)
#if !defined(BLAKE3_NO_SSE2)
void blake3_compress_in_place_sse2(uint32_t cv[8],
                                   const uint8_t block[BLAKE3_BLOCK_LEN],
                                   uint8_t block_len, uint64_t counter,
                                   uint8_t flags);
void blake3_compress_xof_sse2(const uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags, uint8_t out[64]);
void blake3_hash_many_sse2(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_SSE41)
void blake3_compress_in_place_sse41(uint32_t cv[8],
                                    const uint8_t block[BLAKE3_BLOCK_LEN],
                                    uint8_t block_len, uint64_t counter,
                                    uint8_t flags);
void blake3_compress_xof_sse41(const uint32_t cv[8],
                               const uint8_t block[BLAKE3_BLOCK_LEN],
                               uint8_t block_len, uint64_t counter,
                               uint8_t flags, uint8_t out[64]);
void blake3_hash_many_sse41(const uint8_t *const *inputs, size_t num_inputs,
                            size_t blocks, const uint32_t key[8],
                            uint64_t counter, bool increment_counter,
                            uint8_t flags, uint8_t flags_start,
                            uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX2)
void blake3_hash_many_avx2(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX512)
void blake3_compress_in_place_avx512(uint32_t cv[8],
                                     const uint8_t block[BLAKE3_BLOCK_LEN],
                                     uint8_t block_len, uint64_t counter,
                                     uint8_t flags);

void blake3_compress_xof_avx512(const uint32_t cv[8],
                                const uint8_t block[BLAKE3_BLOCK_LEN],
                                uint8_t block_len, uint64_t counter,
                                uint8_t flags, uint8_t out[64]);

void blake3_hash_many_avx512(const uint8_t *const *inputs, size_t num_inputs,
                             size_t blocks, const uint32_t key[8],
                             uint64_t counter, bool increment_counter,
                             uint8_t flags, uint8_t flags_start,
                             uint8_t flags_end, uint8_t *out);

#if !defined(_WIN32) && !defined(__CYGWIN__)
void blake3_xof_many_avx512(const uint32_t cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len, uint64_t counter, uint8_t flags,
                            uint8_t* out, size_t outblocks);
#endif
#endif
#endif

#if BLAKE3_USE_NEON == 1
void blake3_hash_many_neon(const uint8_t *const *inputs, size_t num_inputs,
                           size_t blocks, const uint32_t key[8],
                           uint64_t counter, bool increment_counter,
                           uint8_t flags, uint8_t flags_start,
                           uint8_t flags_end, uint8_t *out);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_IMPL_H */

/* --- End: c/blake3_impl.h --- */

/* --- Begin: c/blake3_portable.c --- */
#include "blake3_impl.h"

INLINE uint32_t rotr32(uint32_t w, uint32_t c) {
  return (w >> c) | (w << (32 - c));
}

INLINE void g(uint32_t *state, size_t a, size_t b, size_t c, size_t d,
              uint32_t x, uint32_t y) {
  state[a] = state[a] + state[b] + x;
  state[d] = rotr32(state[d] ^ state[a], 16);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 12);
  state[a] = state[a] + state[b] + y;
  state[d] = rotr32(state[d] ^ state[a], 8);
  state[c] = state[c] + state[d];
  state[b] = rotr32(state[b] ^ state[c], 7);
}

INLINE void round_fn(uint32_t state[16], const uint32_t *msg, size_t round) {
  // Select the message schedule based on the round.
  const uint8_t *schedule = MSG_SCHEDULE[round];

  // Mix the columns.
  g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
  g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
  g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
  g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

  // Mix the rows.
  g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
  g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
  g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
  g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

INLINE void compress_pre(uint32_t state[16], const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags) {
  uint32_t block_words[16];
  block_words[0] = load32(block + 4 * 0);
  block_words[1] = load32(block + 4 * 1);
  block_words[2] = load32(block + 4 * 2);
  block_words[3] = load32(block + 4 * 3);
  block_words[4] = load32(block + 4 * 4);
  block_words[5] = load32(block + 4 * 5);
  block_words[6] = load32(block + 4 * 6);
  block_words[7] = load32(block + 4 * 7);
  block_words[8] = load32(block + 4 * 8);
  block_words[9] = load32(block + 4 * 9);
  block_words[10] = load32(block + 4 * 10);
  block_words[11] = load32(block + 4 * 11);
  block_words[12] = load32(block + 4 * 12);
  block_words[13] = load32(block + 4 * 13);
  block_words[14] = load32(block + 4 * 14);
  block_words[15] = load32(block + 4 * 15);

  state[0] = cv[0];
  state[1] = cv[1];
  state[2] = cv[2];
  state[3] = cv[3];
  state[4] = cv[4];
  state[5] = cv[5];
  state[6] = cv[6];
  state[7] = cv[7];
  state[8] = IV[0];
  state[9] = IV[1];
  state[10] = IV[2];
  state[11] = IV[3];
  state[12] = counter_low(counter);
  state[13] = counter_high(counter);
  state[14] = (uint32_t)block_len;
  state[15] = (uint32_t)flags;

  round_fn(state, &block_words[0], 0);
  round_fn(state, &block_words[0], 1);
  round_fn(state, &block_words[0], 2);
  round_fn(state, &block_words[0], 3);
  round_fn(state, &block_words[0], 4);
  round_fn(state, &block_words[0], 5);
  round_fn(state, &block_words[0], 6);
}

void blake3_compress_in_place_portable(uint32_t cv[8],
                                       const uint8_t block[BLAKE3_BLOCK_LEN],
                                       uint8_t block_len, uint64_t counter,
                                       uint8_t flags) {
  uint32_t state[16];
  compress_pre(state, cv, block, block_len, counter, flags);
  cv[0] = state[0] ^ state[8];
  cv[1] = state[1] ^ state[9];
  cv[2] = state[2] ^ state[10];
  cv[3] = state[3] ^ state[11];
  cv[4] = state[4] ^ state[12];
  cv[5] = state[5] ^ state[13];
  cv[6] = state[6] ^ state[14];
  cv[7] = state[7] ^ state[15];
}

void blake3_compress_xof_portable(const uint32_t cv[8],
                                  const uint8_t block[BLAKE3_BLOCK_LEN],
                                  uint8_t block_len, uint64_t counter,
                                  uint8_t flags, uint8_t out[64]) {
  uint32_t state[16];
  compress_pre(state, cv, block, block_len, counter, flags);

  store32(&out[0 * 4], state[0] ^ state[8]);
  store32(&out[1 * 4], state[1] ^ state[9]);
  store32(&out[2 * 4], state[2] ^ state[10]);
  store32(&out[3 * 4], state[3] ^ state[11]);
  store32(&out[4 * 4], state[4] ^ state[12]);
  store32(&out[5 * 4], state[5] ^ state[13]);
  store32(&out[6 * 4], state[6] ^ state[14]);
  store32(&out[7 * 4], state[7] ^ state[15]);
  store32(&out[8 * 4], state[8] ^ cv[0]);
  store32(&out[9 * 4], state[9] ^ cv[1]);
  store32(&out[10 * 4], state[10] ^ cv[2]);
  store32(&out[11 * 4], state[11] ^ cv[3]);
  store32(&out[12 * 4], state[12] ^ cv[4]);
  store32(&out[13 * 4], state[13] ^ cv[5]);
  store32(&out[14 * 4], state[14] ^ cv[6]);
  store32(&out[15 * 4], state[15] ^ cv[7]);
}

INLINE void hash_one_portable(const uint8_t *input, size_t blocks,
                              const uint32_t key[8], uint64_t counter,
                              uint8_t flags, uint8_t flags_start,
                              uint8_t flags_end, uint8_t out[BLAKE3_OUT_LEN]) {
  uint32_t cv[8];
  memcpy(cv, key, BLAKE3_KEY_LEN);
  uint8_t block_flags = flags | flags_start;
  while (blocks > 0) {
    if (blocks == 1) {
      block_flags |= flags_end;
    }
    blake3_compress_in_place_portable(cv, input, BLAKE3_BLOCK_LEN, counter,
                                      block_flags);
    input = &input[BLAKE3_BLOCK_LEN];
    blocks -= 1;
    block_flags = flags;
  }
  store_cv_words(out, cv);
}

void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                               size_t blocks, const uint32_t key[8],
                               uint64_t counter, bool increment_counter,
                               uint8_t flags, uint8_t flags_start,
                               uint8_t flags_end, uint8_t *out) {
  while (num_inputs > 0) {
    hash_one_portable(inputs[0], blocks, key, counter, flags, flags_start,
                      flags_end, out);
    if (increment_counter) {
      counter += 1;
    }
    inputs += 1;
    num_inputs -= 1;
    out = &out[BLAKE3_OUT_LEN];
  }
}

/* --- End: c/blake3_portable.c --- */

/* --- Begin: c/blake3_dispatch.c --- */


#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#define BLAKE3_MSAN_UNPOISON(ptr, size) __msan_unpoison((ptr), (size))
#endif
#endif
#if !defined(BLAKE3_MSAN_UNPOISON) && defined(__MEMORY_SANITIZER__)
#define BLAKE3_MSAN_UNPOISON(ptr, size) __msan_unpoison((ptr), (size))
#endif
#ifndef BLAKE3_MSAN_UNPOISON
#define BLAKE3_MSAN_UNPOISON(ptr, size) ((void)0)
#endif

#if defined(_MSC_VER)
#include <Windows.h>
#endif

#if defined(IS_X86)
#if defined(_MSC_VER)
#elif defined(__GNUC__)
#include <immintrin.h>
#else
#undef IS_X86 /* Unimplemented! */
#endif
#endif

#if !defined(BLAKE3_ATOMICS)
#if defined(__has_include)
#if __has_include(<stdatomic.h>) && !defined(_MSC_VER)
#define BLAKE3_ATOMICS 1
#else
#define BLAKE3_ATOMICS 0
#endif /* __has_include(<stdatomic.h>) && !defined(_MSC_VER) */
#else
#define BLAKE3_ATOMICS 0
#endif /* defined(__has_include) */
#endif /* BLAKE3_ATOMICS */

#if BLAKE3_ATOMICS
#define ATOMIC_INT _Atomic int
#define ATOMIC_LOAD(x) x
#define ATOMIC_STORE(x, y) x = y
#elif defined(_MSC_VER)
#define ATOMIC_INT LONG
#define ATOMIC_LOAD(x) InterlockedOr(&x, 0)
#define ATOMIC_STORE(x, y) InterlockedExchange(&x, y)
#else
#define ATOMIC_INT int
#define ATOMIC_LOAD(x) x
#define ATOMIC_STORE(x, y) x = y
#endif

#define MAYBE_UNUSED(x) (void)((x))

#if defined(IS_X86)
static uint64_t xgetbv(void) {
#if defined(_MSC_VER)
  return _xgetbv(0);
#else
  uint32_t eax = 0, edx = 0;
  __asm__ __volatile__("xgetbv\n" : "=a"(eax), "=d"(edx) : "c"(0));
  return ((uint64_t)edx << 32) | eax;
#endif
}

static void cpuid(uint32_t out[4], uint32_t id) {
#if defined(_MSC_VER)
  __cpuid((int *)out, id);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#endif
}

static void cpuidex(uint32_t out[4], uint32_t id, uint32_t sid) {
#if defined(_MSC_VER)
  __cpuidex((int *)out, id, sid);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#endif
}


enum cpu_feature {
  SSE2 = 1 << 0,
  SSSE3 = 1 << 1,
  SSE41 = 1 << 2,
  AVX = 1 << 3,
  AVX2 = 1 << 4,
  AVX512F = 1 << 5,
  AVX512VL = 1 << 6,
  /* ... */
  UNDEFINED = 1 << 30
};

#if !defined(BLAKE3_TESTING)
static /* Allow the variable to be controlled manually for testing */
#endif
    ATOMIC_INT g_cpu_features = UNDEFINED;

#if !defined(BLAKE3_TESTING)
static
#endif
    enum cpu_feature
    get_cpu_features(void) {

  /* If TSAN detects a data race here, try compiling with -DBLAKE3_ATOMICS=1 */
  enum cpu_feature features = ATOMIC_LOAD(g_cpu_features);
  if (features != UNDEFINED) {
    return features;
  } else {
#if defined(IS_X86)
    uint32_t regs[4] = {0};
    uint32_t *eax = &regs[0], *ebx = &regs[1], *ecx = &regs[2], *edx = &regs[3];
    (void)edx;
    features = 0;
    cpuid(regs, 0);
    const int max_id = *eax;
    cpuid(regs, 1);
#if defined(__amd64__) || defined(_M_X64)
    features |= SSE2;
#else
    if (*edx & (1UL << 26))
      features |= SSE2;
#endif
    if (*ecx & (1UL << 9))
      features |= SSSE3;
    if (*ecx & (1UL << 19))
      features |= SSE41;

    if (*ecx & (1UL << 27)) { // OSXSAVE
      const uint64_t mask = xgetbv();
      if ((mask & 6) == 6) { // SSE and AVX states
        if (*ecx & (1UL << 28))
          features |= AVX;
        if (max_id >= 7) {
          cpuidex(regs, 7, 0);
          if (*ebx & (1UL << 5))
            features |= AVX2;
          if ((mask & 224) == 224) { // Opmask, ZMM_Hi256, Hi16_Zmm
            if (*ebx & (1UL << 31))
              features |= AVX512VL;
            if (*ebx & (1UL << 16))
              features |= AVX512F;
          }
        }
      }
    }
    ATOMIC_STORE(g_cpu_features, features);
    return features;
#else
    /* How to detect NEON? */
    return 0;
#endif
  }
}
#endif

void blake3_compress_in_place(uint32_t cv[8],
                              const uint8_t block[BLAKE3_BLOCK_LEN],
                              uint8_t block_len, uint64_t counter,
                              uint8_t flags) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if (features & AVX512VL) {
    blake3_compress_in_place_avx512(cv, block, block_len, counter, flags);
    BLAKE3_MSAN_UNPOISON(cv, 32);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    blake3_compress_in_place_sse41(cv, block, block_len, counter, flags);
    BLAKE3_MSAN_UNPOISON(cv, 32);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    blake3_compress_in_place_sse2(cv, block, block_len, counter, flags);
    BLAKE3_MSAN_UNPOISON(cv, 32);
    return;
  }
#endif
#endif
  blake3_compress_in_place_portable(cv, block, block_len, counter, flags);
}

void blake3_compress_xof(const uint32_t cv[8],
                         const uint8_t block[BLAKE3_BLOCK_LEN],
                         uint8_t block_len, uint64_t counter, uint8_t flags,
                         uint8_t out[64]) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if (features & AVX512VL) {
    blake3_compress_xof_avx512(cv, block, block_len, counter, flags, out);
    BLAKE3_MSAN_UNPOISON(out, 64);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    blake3_compress_xof_sse41(cv, block, block_len, counter, flags, out);
    BLAKE3_MSAN_UNPOISON(out, 64);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    blake3_compress_xof_sse2(cv, block, block_len, counter, flags, out);
    BLAKE3_MSAN_UNPOISON(out, 64);
    return;
  }
#endif
#endif
  blake3_compress_xof_portable(cv, block, block_len, counter, flags, out);
}


void blake3_xof_many(const uint32_t cv[8],
                     const uint8_t block[BLAKE3_BLOCK_LEN],
                     uint8_t block_len, uint64_t counter, uint8_t flags,
                     uint8_t out[64], size_t outblocks) {
  if (outblocks == 0) {
    // The current assembly implementation always outputs at least 1 block.
    return;
  }
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(_WIN32) && !defined(__CYGWIN__) && !defined(BLAKE3_NO_AVX512)
  if (features & AVX512VL) {
    blake3_xof_many_avx512(cv, block, block_len, counter, flags, out, outblocks);
    BLAKE3_MSAN_UNPOISON(out, outblocks * 64);
    return;
  }
#endif
#endif
  for(size_t i = 0; i < outblocks; ++i) {
    blake3_compress_xof(cv, block, block_len, counter + i, flags, out + 64*i);
  }
}

void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                      size_t blocks, const uint32_t key[8], uint64_t counter,
                      bool increment_counter, uint8_t flags,
                      uint8_t flags_start, uint8_t flags_end, uint8_t *out) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if ((features & (AVX512F|AVX512VL)) == (AVX512F|AVX512VL)) {
    blake3_hash_many_avx512(inputs, num_inputs, blocks, key, counter,
                            increment_counter, flags, flags_start, flags_end,
                            out);
    BLAKE3_MSAN_UNPOISON(out, num_inputs * 32);
    return;
  }
#endif
#if !defined(BLAKE3_NO_AVX2)
  if (features & AVX2) {
    blake3_hash_many_avx2(inputs, num_inputs, blocks, key, counter,
                          increment_counter, flags, flags_start, flags_end,
                          out);
    BLAKE3_MSAN_UNPOISON(out, num_inputs * 32);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    blake3_hash_many_sse41(inputs, num_inputs, blocks, key, counter,
                           increment_counter, flags, flags_start, flags_end,
                           out);
    BLAKE3_MSAN_UNPOISON(out, num_inputs * 32);
    return;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    blake3_hash_many_sse2(inputs, num_inputs, blocks, key, counter,
                          increment_counter, flags, flags_start, flags_end,
                          out);
    BLAKE3_MSAN_UNPOISON(out, num_inputs * 32);
    return;
  }
#endif
#endif

#if BLAKE3_USE_NEON == 1
  blake3_hash_many_neon(inputs, num_inputs, blocks, key, counter,
                        increment_counter, flags, flags_start, flags_end, out);
  return;
#endif

  blake3_hash_many_portable(inputs, num_inputs, blocks, key, counter,
                            increment_counter, flags, flags_start, flags_end,
                            out);
}

// The dynamically detected SIMD degree of the current platform.
size_t blake3_simd_degree(void) {
#if defined(IS_X86)
  const enum cpu_feature features = get_cpu_features();
  MAYBE_UNUSED(features);
#if !defined(BLAKE3_NO_AVX512)
  if ((features & (AVX512F|AVX512VL)) == (AVX512F|AVX512VL)) {
    return 16;
  }
#endif
#if !defined(BLAKE3_NO_AVX2)
  if (features & AVX2) {
    return 8;
  }
#endif
#if !defined(BLAKE3_NO_SSE41)
  if (features & SSE41) {
    return 4;
  }
#endif
#if !defined(BLAKE3_NO_SSE2)
  if (features & SSE2) {
    return 4;
  }
#endif
#endif
#if BLAKE3_USE_NEON == 1
  return 4;
#endif
  return 1;
}

/* --- End: c/blake3_dispatch.c --- */

/* --- Begin: c/blake3.c --- */


const char *blake3_version(void) { return BLAKE3_VERSION_STRING; }

INLINE void chunk_state_init(blake3_chunk_state *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
  self->blocks_compressed = 0;
  self->flags = flags;
}

INLINE void chunk_state_reset(blake3_chunk_state *self, const uint32_t key[8],
                              uint64_t chunk_counter) {
  memcpy(self->cv, key, BLAKE3_KEY_LEN);
  self->chunk_counter = chunk_counter;
  self->blocks_compressed = 0;
  memset(self->buf, 0, BLAKE3_BLOCK_LEN);
  self->buf_len = 0;
}

INLINE size_t chunk_state_len(const blake3_chunk_state *self) {
  return (BLAKE3_BLOCK_LEN * (size_t)self->blocks_compressed) +
         ((size_t)self->buf_len);
}

INLINE size_t chunk_state_fill_buf(blake3_chunk_state *self,
                                   const uint8_t *input, size_t input_len) {
  size_t take = BLAKE3_BLOCK_LEN - ((size_t)self->buf_len);
  if (take > input_len) {
    take = input_len;
  }
  uint8_t *dest = self->buf + ((size_t)self->buf_len);
  memcpy(dest, input, take);
  self->buf_len += (uint8_t)take;
  return take;
}

INLINE uint8_t chunk_state_maybe_start_flag(const blake3_chunk_state *self) {
  if (self->blocks_compressed == 0) {
    return CHUNK_START;
  } else {
    return 0;
  }
}

typedef struct {
  uint32_t input_cv[8];
  uint64_t counter;
  uint8_t block[BLAKE3_BLOCK_LEN];
  uint8_t block_len;
  uint8_t flags;
} output_t;

INLINE output_t make_output(const uint32_t input_cv[8],
                            const uint8_t block[BLAKE3_BLOCK_LEN],
                            uint8_t block_len, uint64_t counter,
                            uint8_t flags) {
  output_t ret;
  memcpy(ret.input_cv, input_cv, 32);
  memcpy(ret.block, block, BLAKE3_BLOCK_LEN);
  ret.block_len = block_len;
  ret.counter = counter;
  ret.flags = flags;
  return ret;
}

// Chaining values within a given chunk (specifically the compress_in_place
// interface) are represented as words. This avoids unnecessary bytes<->words
// conversion overhead in the portable implementation. However, the hash_many
// interface handles both user input and parent node blocks, so it accepts
// bytes. For that reason, chaining values in the CV stack are represented as
// bytes.
INLINE void output_chaining_value(const output_t *self, uint8_t cv[32]) {
  uint32_t cv_words[8];
  memcpy(cv_words, self->input_cv, 32);
  blake3_compress_in_place(cv_words, self->block, self->block_len,
                           self->counter, self->flags);
  store_cv_words(cv, cv_words);
}

INLINE void output_root_bytes(const output_t *self, uint64_t seek, uint8_t *out,
                              size_t out_len) {
  if (out_len == 0) {
      return;
  }
  uint64_t output_block_counter = seek / 64;
  size_t offset_within_block = seek % 64;
  uint8_t wide_buf[64];
  if(offset_within_block) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, wide_buf);
    const size_t available_bytes = 64 - offset_within_block;
    const size_t bytes = out_len > available_bytes ? available_bytes : out_len;
    memcpy(out, wide_buf + offset_within_block, bytes);
    out += bytes;
    out_len -= bytes;
    output_block_counter += 1;
  }
  if(out_len / 64) {
    blake3_xof_many(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, out, out_len / 64);
  }
  output_block_counter += out_len / 64;
  out += out_len & -64;
  out_len -= out_len & -64;
  if(out_len) {
    blake3_compress_xof(self->input_cv, self->block, self->block_len, output_block_counter, self->flags | ROOT, wide_buf);
    memcpy(out, wide_buf, out_len);
  }
}

INLINE void chunk_state_update(blake3_chunk_state *self, const uint8_t *input,
                               size_t input_len) {
  if (self->buf_len > 0) {
    size_t take = chunk_state_fill_buf(self, input, input_len);
    input += take;
    input_len -= take;
    if (input_len > 0) {
      blake3_compress_in_place(
          self->cv, self->buf, BLAKE3_BLOCK_LEN, self->chunk_counter,
          self->flags | chunk_state_maybe_start_flag(self));
      self->blocks_compressed += 1;
      self->buf_len = 0;
      memset(self->buf, 0, BLAKE3_BLOCK_LEN);
    }
  }

  while (input_len > BLAKE3_BLOCK_LEN) {
    blake3_compress_in_place(self->cv, input, BLAKE3_BLOCK_LEN,
                             self->chunk_counter,
                             self->flags | chunk_state_maybe_start_flag(self));
    self->blocks_compressed += 1;
    input += BLAKE3_BLOCK_LEN;
    input_len -= BLAKE3_BLOCK_LEN;
  }

  chunk_state_fill_buf(self, input, input_len);
}

INLINE output_t chunk_state_output(const blake3_chunk_state *self) {
  uint8_t block_flags =
      self->flags | chunk_state_maybe_start_flag(self) | CHUNK_END;
  return make_output(self->cv, self->buf, self->buf_len, self->chunk_counter,
                     block_flags);
}

INLINE output_t parent_output(const uint8_t block[BLAKE3_BLOCK_LEN],
                              const uint32_t key[8], uint8_t flags) {
  return make_output(key, block, BLAKE3_BLOCK_LEN, 0, flags | PARENT);
}

// Given some input larger than one chunk, return the number of bytes that
// should go in the left subtree. This is the largest power-of-2 number of
// chunks that leaves at least 1 byte for the right subtree.
INLINE size_t left_subtree_len(size_t input_len) {
  // Subtract 1 to reserve at least one byte for the right side. input_len
  // should always be greater than BLAKE3_CHUNK_LEN.
  size_t full_chunks = (input_len - 1) / BLAKE3_CHUNK_LEN;
  return round_down_to_power_of_2(full_chunks) * BLAKE3_CHUNK_LEN;
}

// Use SIMD parallelism to hash up to MAX_SIMD_DEGREE chunks at the same time
// on a single thread. Write out the chunk chaining values and return the
// number of chunks hashed. These chunks are never the root and never empty;
// those cases use a different codepath.
INLINE size_t compress_chunks_parallel(const uint8_t *input, size_t input_len,
                                       const uint32_t key[8],
                                       uint64_t chunk_counter, uint8_t flags,
                                       uint8_t *out) {
#if defined(BLAKE3_TESTING)
  assert(0 < input_len);
  assert(input_len <= MAX_SIMD_DEGREE * BLAKE3_CHUNK_LEN);
#endif

  const uint8_t *chunks_array[MAX_SIMD_DEGREE];
  size_t input_position = 0;
  size_t chunks_array_len = 0;
  while (input_len - input_position >= BLAKE3_CHUNK_LEN) {
    chunks_array[chunks_array_len] = &input[input_position];
    input_position += BLAKE3_CHUNK_LEN;
    chunks_array_len += 1;
  }

  blake3_hash_many(chunks_array, chunks_array_len,
                   BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, key, chunk_counter,
                   true, flags, CHUNK_START, CHUNK_END, out);

  // Hash the remaining partial chunk, if there is one. Note that the empty
  // chunk (meaning the empty message) is a different codepath.
  if (input_len > input_position) {
    uint64_t counter = chunk_counter + (uint64_t)chunks_array_len;
    blake3_chunk_state chunk_state;
    chunk_state_init(&chunk_state, key, flags);
    chunk_state.chunk_counter = counter;
    chunk_state_update(&chunk_state, &input[input_position],
                       input_len - input_position);
    output_t output = chunk_state_output(&chunk_state);
    output_chaining_value(&output, &out[chunks_array_len * BLAKE3_OUT_LEN]);
    return chunks_array_len + 1;
  } else {
    return chunks_array_len;
  }
}

// Use SIMD parallelism to hash up to MAX_SIMD_DEGREE parents at the same time
// on a single thread. Write out the parent chaining values and return the
// number of parents hashed. (If there's an odd input chaining value left over,
// return it as an additional output.) These parents are never the root and
// never empty; those cases use a different codepath.
INLINE size_t compress_parents_parallel(const uint8_t *child_chaining_values,
                                        size_t num_chaining_values,
                                        const uint32_t key[8], uint8_t flags,
                                        uint8_t *out) {
#if defined(BLAKE3_TESTING)
  assert(2 <= num_chaining_values);
  assert(num_chaining_values <= 2 * MAX_SIMD_DEGREE_OR_2);
#endif

  const uint8_t *parents_array[MAX_SIMD_DEGREE_OR_2];
  size_t parents_array_len = 0;
  while (num_chaining_values - (2 * parents_array_len) >= 2) {
    parents_array[parents_array_len] =
        &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN];
    parents_array_len += 1;
  }

  blake3_hash_many(parents_array, parents_array_len, 1, key,
                   0, // Parents always use counter 0.
                   false, flags | PARENT,
                   0, // Parents have no start flags.
                   0, // Parents have no end flags.
                   out);

  // If there's an odd child left over, it becomes an output.
  if (num_chaining_values > 2 * parents_array_len) {
    memcpy(&out[parents_array_len * BLAKE3_OUT_LEN],
           &child_chaining_values[2 * parents_array_len * BLAKE3_OUT_LEN],
           BLAKE3_OUT_LEN);
    return parents_array_len + 1;
  } else {
    return parents_array_len;
  }
}

// The wide helper function returns (writes out) an array of chaining values
// and returns the length of that array. The number of chaining values returned
// is the dynamically detected SIMD degree, at most MAX_SIMD_DEGREE. Or fewer,
// if the input is shorter than that many chunks. The reason for maintaining a
// wide array of chaining values going back up the tree, is to allow the
// implementation to hash as many parents in parallel as possible.
//
// As a special case when the SIMD degree is 1, this function will still return
// at least 2 outputs. This guarantees that this function doesn't perform the
// root compression. (If it did, it would use the wrong flags, and also we
// wouldn't be able to implement extendable output.) Note that this function is
// not used when the whole input is only 1 chunk long; that's a different
// codepath.
//
// Why not just have the caller split the input on the first update(), instead
// of implementing this special rule? Because we don't want to limit SIMD or
// multi-threading parallelism for that update().
size_t blake3_compress_subtree_wide(const uint8_t *input, size_t input_len,
                                    const uint32_t key[8],
                                    uint64_t chunk_counter, uint8_t flags,
                                    uint8_t *out, bool use_tbb) {
  // Note that the single chunk case does *not* bump the SIMD degree up to 2
  // when it is 1. If this implementation adds multi-threading in the future,
  // this gives us the option of multi-threading even the 2-chunk case, which
  // can help performance on smaller platforms.
  if (input_len <= blake3_simd_degree() * BLAKE3_CHUNK_LEN) {
    return compress_chunks_parallel(input, input_len, key, chunk_counter, flags,
                                    out);
  }

  // With more than simd_degree chunks, we need to recurse. Start by dividing
  // the input into left and right subtrees. (Note that this is only optimal
  // as long as the SIMD degree is a power of 2. If we ever get a SIMD degree
  // of 3 or something, we'll need a more complicated strategy.)
  size_t left_input_len = left_subtree_len(input_len);
  size_t right_input_len = input_len - left_input_len;
  const uint8_t *right_input = &input[left_input_len];
  uint64_t right_chunk_counter =
      chunk_counter + (uint64_t)(left_input_len / BLAKE3_CHUNK_LEN);

  // Make space for the child outputs. Here we use MAX_SIMD_DEGREE_OR_2 to
  // account for the special case of returning 2 outputs when the SIMD degree
  // is 1.
  uint8_t cv_array[2 * MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t degree = blake3_simd_degree();
  if (left_input_len > BLAKE3_CHUNK_LEN && degree == 1) {
    // The special case: We always use a degree of at least two, to make
    // sure there are two outputs. Except, as noted above, at the chunk
    // level, where we allow degree=1. (Note that the 1-chunk-input case is
    // a different codepath.)
    degree = 2;
  }
  uint8_t *right_cvs = &cv_array[degree * BLAKE3_OUT_LEN];

  // Recurse!
  size_t left_n = SIZE_MAX;
  size_t right_n = SIZE_MAX;

#if defined(BLAKE3_USE_TBB)
  blake3_compress_subtree_wide_join_tbb(
      key, flags, use_tbb,
      // left-hand side
      input, left_input_len, chunk_counter, cv_array, &left_n,
      // right-hand side
      right_input, right_input_len, right_chunk_counter, right_cvs, &right_n);
#elif defined(BLAKE3PLUS_ENABLE_PTHREAD)
  blake3plus_compress_subtree_wide_join_pthread(
      key, flags, use_tbb,
      // left-hand side
      input, left_input_len, chunk_counter, cv_array, &left_n,
      // right-hand side
      right_input, right_input_len, right_chunk_counter, right_cvs, &right_n);
#else
  left_n = blake3_compress_subtree_wide(
      input, left_input_len, key, chunk_counter, flags, cv_array, use_tbb);
  right_n = blake3_compress_subtree_wide(right_input, right_input_len, key,
                                         right_chunk_counter, flags, right_cvs,
                                         use_tbb);
#endif // BLAKE3_USE_TBB

  // The special case again. If simd_degree=1, then we'll have left_n=1 and
  // right_n=1. Rather than compressing them into a single output, return
  // them directly, to make sure we always have at least two outputs.
  if (left_n == 1) {
    memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
    return 2;
  }

  // Otherwise, do one layer of parent node compression.
  size_t num_chaining_values = left_n + right_n;
  return compress_parents_parallel(cv_array, num_chaining_values, key, flags,
                                   out);
}

// Hash a subtree with compress_subtree_wide(), and then condense the resulting
// list of chaining values down to a single parent node. Don't compress that
// last parent node, however. Instead, return its message bytes (the
// concatenated chaining values of its children). This is necessary when the
// first call to update() supplies a complete subtree, because the topmost
// parent node of that subtree could end up being the root. It's also necessary
// for extended output in the general case.
//
// As with compress_subtree_wide(), this function is not used on inputs of 1
// chunk or less. That's a different codepath.
INLINE void
compress_subtree_to_parent_node(const uint8_t *input, size_t input_len,
                                const uint32_t key[8], uint64_t chunk_counter,
                                uint8_t flags, uint8_t out[2 * BLAKE3_OUT_LEN],
                                bool use_tbb) {
#if defined(BLAKE3_TESTING)
  assert(input_len > BLAKE3_CHUNK_LEN);
#endif

  uint8_t cv_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN];
  size_t num_cvs = blake3_compress_subtree_wide(input, input_len, key,
                                                chunk_counter, flags, cv_array, use_tbb);
  assert(num_cvs <= MAX_SIMD_DEGREE_OR_2);
  // The following loop never executes when MAX_SIMD_DEGREE_OR_2 is 2, because
  // as we just asserted, num_cvs will always be <=2 in that case. But GCC
  // (particularly GCC 8.5) can't tell that it never executes, and if NDEBUG is
  // set then it emits incorrect warnings here. We tried a few different
  // hacks to silence these, but in the end our hacks just produced different
  // warnings (see https://github.com/BLAKE3-team/BLAKE3/pull/380). Out of
  // desperation, we ifdef out this entire loop when we know it's not needed.
#if MAX_SIMD_DEGREE_OR_2 > 2
  // If MAX_SIMD_DEGREE_OR_2 is greater than 2 and there's enough input,
  // compress_subtree_wide() returns more than 2 chaining values. Condense
  // them into 2 by forming parent nodes repeatedly.
  uint8_t out_array[MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN / 2];
  while (num_cvs > 2) {
    num_cvs =
        compress_parents_parallel(cv_array, num_cvs, key, flags, out_array);
    memcpy(cv_array, out_array, num_cvs * BLAKE3_OUT_LEN);
  }
#endif
  memcpy(out, cv_array, 2 * BLAKE3_OUT_LEN);
}

INLINE void hasher_init_base(blake3_hasher *self, const uint32_t key[8],
                             uint8_t flags) {
  memcpy(self->key, key, BLAKE3_KEY_LEN);
  chunk_state_init(&self->chunk, key, flags);
  self->cv_stack_len = 0;
}

void blake3_hasher_init(blake3_hasher *self) { hasher_init_base(self, IV, 0); }

void blake3_hasher_init_keyed(blake3_hasher *self,
                              const uint8_t key[BLAKE3_KEY_LEN]) {
  uint32_t key_words[8];
  load_key_words(key, key_words);
  hasher_init_base(self, key_words, KEYED_HASH);
}

void blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context,
                                       size_t context_len) {
  blake3_hasher context_hasher;
  hasher_init_base(&context_hasher, IV, DERIVE_KEY_CONTEXT);
  blake3_hasher_update(&context_hasher, context, context_len);
  uint8_t context_key[BLAKE3_KEY_LEN];
  blake3_hasher_finalize(&context_hasher, context_key, BLAKE3_KEY_LEN);
  uint32_t context_key_words[8];
  load_key_words(context_key, context_key_words);
  hasher_init_base(self, context_key_words, DERIVE_KEY_MATERIAL);
}

void blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
  blake3_hasher_init_derive_key_raw(self, context, strlen(context));
}

// As described in hasher_push_cv() below, we do "lazy merging", delaying
// merges until right before the next CV is about to be added. This is
// different from the reference implementation. Another difference is that we
// aren't always merging 1 chunk at a time. Instead, each CV might represent
// any power-of-two number of chunks, as long as the smaller-above-larger stack
// order is maintained. Instead of the "count the trailing 0-bits" algorithm
// described in the spec, we use a "count the total number of 1-bits" variant
// that doesn't require us to retain the subtree size of the CV on top of the
// stack. The principle is the same: each CV that should remain in the stack is
// represented by a 1-bit in the total number of chunks (or bytes) so far.
INLINE void hasher_merge_cv_stack(blake3_hasher *self, uint64_t total_len) {
  size_t post_merge_stack_len = (size_t)popcnt(total_len);
  while (self->cv_stack_len > post_merge_stack_len) {
    uint8_t *parent_node =
        &self->cv_stack[(self->cv_stack_len - 2) * BLAKE3_OUT_LEN];
    output_t output = parent_output(parent_node, self->key, self->chunk.flags);
    output_chaining_value(&output, parent_node);
    self->cv_stack_len -= 1;
  }
}

// In reference_impl.rs, we merge the new CV with existing CVs from the stack
// before pushing it. We can do that because we know more input is coming, so
// we know none of the merges are root.
//
// This setting is different. We want to feed as much input as possible to
// compress_subtree_wide(), without setting aside anything for the chunk_state.
// If the user gives us 64 KiB, we want to parallelize over all 64 KiB at once
// as a single subtree, if at all possible.
//
// This leads to two problems:
// 1) This 64 KiB input might be the only call that ever gets made to update.
//    In this case, the root node of the 64 KiB subtree would be the root node
//    of the whole tree, and it would need to be ROOT finalized. We can't
//    compress it until we know.
// 2) This 64 KiB input might complete a larger tree, whose root node is
//    similarly going to be the root of the whole tree. For example, maybe
//    we have 196 KiB (that is, 128 + 64) hashed so far. We can't compress the
//    node at the root of the 256 KiB subtree until we know how to finalize it.
//
// The second problem is solved with "lazy merging". That is, when we're about
// to add a CV to the stack, we don't merge it with anything first, as the
// reference impl does. Instead we do merges using the *previous* CV that was
// added, which is sitting on top of the stack, and we put the new CV
// (unmerged) on top of the stack afterwards. This guarantees that we never
// merge the root node until finalize().
//
// Solving the first problem requires an additional tool,
// compress_subtree_to_parent_node(). That function always returns the top
// *two* chaining values of the subtree it's compressing. We then do lazy
// merging with each of them separately, so that the second CV will always
// remain unmerged. (That also helps us support extendable output when we're
// hashing an input all-at-once.)
INLINE void hasher_push_cv(blake3_hasher *self, uint8_t new_cv[BLAKE3_OUT_LEN],
                           uint64_t chunk_counter) {
  hasher_merge_cv_stack(self, chunk_counter);
  memcpy(&self->cv_stack[self->cv_stack_len * BLAKE3_OUT_LEN], new_cv,
         BLAKE3_OUT_LEN);
  self->cv_stack_len += 1;
}

INLINE void blake3_hasher_update_base(blake3_hasher *self, const void *input,
                                      size_t input_len, bool use_tbb) {
  // Explicitly checking for zero avoids causing UB by passing a null pointer
  // to memcpy. This comes up in practice with things like:
  //   std::vector<uint8_t> v;
  //   blake3_hasher_update(&hasher, v.data(), v.size());
  if (input_len == 0) {
    return;
  }

  const uint8_t *input_bytes = (const uint8_t *)input;

  // If we have some partial chunk bytes in the internal chunk_state, we need
  // to finish that chunk first.
  if (chunk_state_len(&self->chunk) > 0) {
    size_t take = BLAKE3_CHUNK_LEN - chunk_state_len(&self->chunk);
    if (take > input_len) {
      take = input_len;
    }
    chunk_state_update(&self->chunk, input_bytes, take);
    input_bytes += take;
    input_len -= take;
    // If we've filled the current chunk and there's more coming, finalize this
    // chunk and proceed. In this case we know it's not the root.
    if (input_len > 0) {
      output_t output = chunk_state_output(&self->chunk);
      uint8_t chunk_cv[32];
      output_chaining_value(&output, chunk_cv);
      hasher_push_cv(self, chunk_cv, self->chunk.chunk_counter);
      chunk_state_reset(&self->chunk, self->key, self->chunk.chunk_counter + 1);
    } else {
      return;
    }
  }

  // Now the chunk_state is clear, and we have more input. If there's more than
  // a single chunk (so, definitely not the root chunk), hash the largest whole
  // subtree we can, with the full benefits of SIMD (and maybe in the future,
  // multi-threading) parallelism. Two restrictions:
  // - The subtree has to be a power-of-2 number of chunks. Only subtrees along
  //   the right edge can be incomplete, and we don't know where the right edge
  //   is going to be until we get to finalize().
  // - The subtree must evenly divide the total number of chunks up until this
  //   point (if total is not 0). If the current incomplete subtree is only
  //   waiting for 1 more chunk, we can't hash a subtree of 4 chunks. We have
  //   to complete the current subtree first.
  // Because we might need to break up the input to form powers of 2, or to
  // evenly divide what we already have, this part runs in a loop.
  while (input_len > BLAKE3_CHUNK_LEN) {
    size_t subtree_len = round_down_to_power_of_2(input_len);
    uint64_t count_so_far = self->chunk.chunk_counter * BLAKE3_CHUNK_LEN;
    // Shrink the subtree_len until it evenly divides the count so far. We know
    // that subtree_len itself is a power of 2, so we can use a bitmasking
    // trick instead of an actual remainder operation. (Note that if the caller
    // consistently passes power-of-2 inputs of the same size, as is hopefully
    // typical, this loop condition will always fail, and subtree_len will
    // always be the full length of the input.)
    //
    // An aside: We don't have to shrink subtree_len quite this much. For
    // example, if count_so_far is 1, we could pass 2 chunks to
    // compress_subtree_to_parent_node. Since we'll get 2 CVs back, we'll still
    // get the right answer in the end, and we might get to use 2-way SIMD
    // parallelism. The problem with this optimization, is that it gets us
    // stuck always hashing 2 chunks. The total number of chunks will remain
    // odd, and we'll never graduate to higher degrees of parallelism. See
    // https://github.com/BLAKE3-team/BLAKE3/issues/69.
    while ((((uint64_t)(subtree_len - 1)) & count_so_far) != 0) {
      subtree_len /= 2;
    }
    // The shrunken subtree_len might now be 1 chunk long. If so, hash that one
    // chunk by itself. Otherwise, compress the subtree into a pair of CVs.
    uint64_t subtree_chunks = subtree_len / BLAKE3_CHUNK_LEN;
    if (subtree_len <= BLAKE3_CHUNK_LEN) {
      blake3_chunk_state chunk_state;
      chunk_state_init(&chunk_state, self->key, self->chunk.flags);
      chunk_state.chunk_counter = self->chunk.chunk_counter;
      chunk_state_update(&chunk_state, input_bytes, subtree_len);
      output_t output = chunk_state_output(&chunk_state);
      uint8_t cv[BLAKE3_OUT_LEN];
      output_chaining_value(&output, cv);
      hasher_push_cv(self, cv, chunk_state.chunk_counter);
    } else {
      // This is the high-performance happy path, though getting here depends
      // on the caller giving us a long enough input.
      uint8_t cv_pair[2 * BLAKE3_OUT_LEN];
      compress_subtree_to_parent_node(input_bytes, subtree_len, self->key,
                                      self->chunk.chunk_counter,
                                      self->chunk.flags, cv_pair, use_tbb);
      hasher_push_cv(self, cv_pair, self->chunk.chunk_counter);
      hasher_push_cv(self, &cv_pair[BLAKE3_OUT_LEN],
                     self->chunk.chunk_counter + (subtree_chunks / 2));
    }
    self->chunk.chunk_counter += subtree_chunks;
    input_bytes += subtree_len;
    input_len -= subtree_len;
  }

  // If there's any remaining input less than a full chunk, add it to the chunk
  // state. In that case, also do a final merge loop to make sure the subtree
  // stack doesn't contain any unmerged pairs. The remaining input means we
  // know these merges are non-root. This merge loop isn't strictly necessary
  // here, because hasher_push_chunk_cv already does its own merge loop, but it
  // simplifies blake3_hasher_finalize below.
  if (input_len > 0) {
    chunk_state_update(&self->chunk, input_bytes, input_len);
    hasher_merge_cv_stack(self, self->chunk.chunk_counter);
  }
}

void blake3_hasher_update(blake3_hasher *self, const void *input,
                          size_t input_len) {
  bool use_tbb = false;
  blake3_hasher_update_base(self, input, input_len, use_tbb);
}

#if defined(BLAKE3_USE_TBB)
void blake3_hasher_update_tbb(blake3_hasher *self, const void *input,
                              size_t input_len) {
  bool use_tbb = true;
  blake3_hasher_update_base(self, input, input_len, use_tbb);
}
#endif // BLAKE3_USE_TBB

#if defined(BLAKE3PLUS_ENABLE_PTHREAD)
void blake3_hasher_update_mt_internal(blake3_hasher *self, const void *input,
                                      size_t input_len) {
  blake3_hasher_update_base(self, input, input_len, true);
}
#endif // BLAKE3PLUS_ENABLE_PTHREAD

void blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out,
                            size_t out_len) {
  blake3_hasher_finalize_seek(self, 0, out, out_len);
}

void blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek,
                                 uint8_t *out, size_t out_len) {
  // Explicitly checking for zero avoids causing UB by passing a null pointer
  // to memcpy. This comes up in practice with things like:
  //   std::vector<uint8_t> v;
  //   blake3_hasher_finalize(&hasher, v.data(), v.size());
  if (out_len == 0) {
    return;
  }

  // If the subtree stack is empty, then the current chunk is the root.
  if (self->cv_stack_len == 0) {
    output_t output = chunk_state_output(&self->chunk);
    output_root_bytes(&output, seek, out, out_len);
    return;
  }
  // If there are any bytes in the chunk state, finalize that chunk and do a
  // roll-up merge between that chunk hash and every subtree in the stack. In
  // this case, the extra merge loop at the end of blake3_hasher_update
  // guarantees that none of the subtrees in the stack need to be merged with
  // each other first. Otherwise, if there are no bytes in the chunk state,
  // then the top of the stack is a chunk hash, and we start the merge from
  // that.
  output_t output;
  size_t cvs_remaining;
  if (chunk_state_len(&self->chunk) > 0) {
    cvs_remaining = self->cv_stack_len;
    output = chunk_state_output(&self->chunk);
  } else {
    // There are always at least 2 CVs in the stack in this case.
    cvs_remaining = self->cv_stack_len - 2;
    output = parent_output(&self->cv_stack[cvs_remaining * 32], self->key,
                           self->chunk.flags);
  }
  while (cvs_remaining > 0) {
    cvs_remaining -= 1;
    uint8_t parent_block[BLAKE3_BLOCK_LEN];
    memcpy(parent_block, &self->cv_stack[cvs_remaining * 32], 32);
    output_chaining_value(&output, &parent_block[32]);
    output = parent_output(parent_block, self->key, self->chunk.flags);
  }
  output_root_bytes(&output, seek, out, out_len);
}

void blake3_hasher_reset(blake3_hasher *self) {
  chunk_state_reset(&self->chunk, self->key, 0);
  self->cv_stack_len = 0;
}

/* --- End: c/blake3.c --- */

/* --- Begin: c/blake3plus.c --- */
#include "blake3plus.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(_WIN32)
#include <windows.h>
#endif

/* Internal hook implemented in blake3.c */
extern void blake3_hasher_update_mt_internal(blake3_hasher *self,
                                             const void *input,
                                             size_t input_len);

#define B3P_MAX_WORKERS 64
#define B3P_MAX_SPIN_ITERS 256
#define B3P_TASK_RING_CAP 256
#define B3P_MAX_MMAP_BYTES (1ULL << 30)
#define B3P_STREAM_BUF_SIZE (4 * 1024 * 1024)

typedef enum {
  B3P_TASK_FREE = 0,
  B3P_TASK_ALLOCATED = 1,
  B3P_TASK_QUEUED = 2,
  B3P_TASK_RUNNING = 3,
  B3P_TASK_DONE = 4
} b3p_slot_state_t;

typedef struct {
  const uint32_t *key;
  uint8_t flags;
  const uint8_t *input;
  size_t input_len;
  uint64_t chunk_counter;
  uint8_t *cvs;
  size_t out_n;
  atomic_int state;
  pthread_mutex_t mtx;
  pthread_cond_t cv;
} b3p_task_slot_t;

static b3p_task_slot_t g_slots[B3P_TASK_RING_CAP];
static pthread_once_t g_slots_once = PTHREAD_ONCE_INIT;

static void b3p_init_slots(void) {
  for (size_t i = 0; i < B3P_TASK_RING_CAP; i++) {
    atomic_init(&g_slots[i].state, B3P_TASK_FREE);
    pthread_mutex_init(&g_slots[i].mtx, NULL);
    pthread_cond_init(&g_slots[i].cv, NULL);
  }
}

typedef struct {
  size_t queue[B3P_TASK_RING_CAP];
  size_t head;
  size_t tail;
  size_t count;
  pthread_mutex_t lock;
  pthread_cond_t cv;
  bool shutdown;
} b3p_ring_queue_t;

static b3p_ring_queue_t g_ring = {
  .head = 0, .tail = 0, .count = 0,
  .lock = PTHREAD_MUTEX_INITIALIZER,
  .cv = PTHREAD_COND_INITIALIZER,
  .shutdown = false
};

static pthread_t g_worker_threads[B3P_MAX_WORKERS];
static atomic_size_t g_num_workers = 0;
static pthread_mutex_t g_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_atfork_once = PTHREAD_ONCE_INIT;
static atomic_bool g_pool_fork_active = false;

#if defined(__linux__)
static size_t b3p_parse_cgroup_v2_cpu_max(const char *path) {
  FILE *fp = fopen(path, "re");
  if (!fp) {
    return 0;
  }
  char quota_str[64] = {0};
  unsigned long long period = 0;
  if (fscanf(fp, "%63s %llu", quota_str, &period) == 2 && period > 0) {
    fclose(fp);
    if (strcmp(quota_str, "max") != 0) {
      unsigned long long quota = strtoull(quota_str, NULL, 10);
      if (quota > 0) {
        size_t cpus = (size_t)((quota + period - 1) / period);
        return (cpus >= 1) ? cpus : 1;
      }
    }
    return 0;
  }
  fclose(fp);
  return 0;
}
#endif

static size_t b3p_get_cgroup_cpu_quota(void) {
#if defined(__linux__)
  const char *cg_root = getenv("BLAKE3PLUS_CGROUP_ROOT");
  bool custom_root = (cg_root != NULL && cg_root[0] != '\0');
  if (!custom_root) {
    cg_root = "/sys/fs/cgroup";
  }

  char path_buf[PATH_MAX];

  if (!custom_root) {
    FILE *fcg = fopen("/proc/self/cgroup", "re");
    if (fcg) {
      char line[512];
      while (fgets(line, sizeof(line), fcg)) {
        if (strncmp(line, "0::/", 4) == 0) {
          char *sub = line + 3;
          size_t len = strlen(sub);
          while (len > 0 && (sub[len - 1] == '\n' || sub[len - 1] == '\r')) {
            sub[--len] = '\0';
          }
          if (len > 1) {
            snprintf(path_buf, sizeof(path_buf), "%s%s/cpu.max", cg_root, sub);
            size_t slice_cpus = b3p_parse_cgroup_v2_cpu_max(path_buf);
            if (slice_cpus > 0) {
              fclose(fcg);
              return slice_cpus;
            }
          }
          break;
        }
      }
      fclose(fcg);
    }
  }

  snprintf(path_buf, sizeof(path_buf), "%s/cpu.max", cg_root);
  size_t v2_cpus = b3p_parse_cgroup_v2_cpu_max(path_buf);
  if (v2_cpus > 0) {
    return v2_cpus;
  }

  char q_path[PATH_MAX], p_path[PATH_MAX];
  snprintf(q_path, sizeof(q_path), "%s/cpu/cpu.cfs_quota_us", cg_root);
  snprintf(p_path, sizeof(p_path), "%s/cpu/cpu.cfs_period_us", cg_root);
  FILE *fq = fopen(q_path, "re");
  FILE *fp1 = fopen(p_path, "re");
  if (fq && fp1) {
    long long quota = -1, period = 0;
    if (fscanf(fq, "%lld", &quota) == 1 && fscanf(fp1, "%lld", &period) == 1) {
      if (quota > 0 && period > 0) {
        fclose(fq);
        fclose(fp1);
        size_t cpus = (size_t)((quota + period - 1) / period);
        return (cpus >= 1) ? cpus : 1;
      }
    }
  }
  if (fq) fclose(fq);
  if (fp1) fclose(fp1);
#endif
  return 0;
}

BLAKE3_API size_t blake3plus_detect_cgroup_cpu_quota(void) {
  return b3p_get_cgroup_cpu_quota();
}

BLAKE3_API size_t blake3plus_get_effective_cpus(void) {
  size_t affinity_cpus = 0;
#if defined(__linux__)
  cpu_set_t set;
  CPU_ZERO(&set);
  if (sched_getaffinity(0, sizeof(set), &set) == 0) {
    int count = CPU_COUNT(&set);
    if (count >= 1) {
      affinity_cpus = (size_t)count;
    }
  }
#elif defined(_WIN32)
  SYSTEM_INFO sysinfo;
  GetSystemInfo(&sysinfo);
  affinity_cpus = (size_t)sysinfo.dwNumberOfProcessors;
#endif
  if (affinity_cpus == 0) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    affinity_cpus = (nprocs >= 1) ? (size_t)nprocs : 1;
  }

  size_t cgroup_cpus = b3p_get_cgroup_cpu_quota();
  if (cgroup_cpus > 0 && cgroup_cpus < affinity_cpus) {
    return cgroup_cpus;
  }
  return affinity_cpus;
}

BLAKE3_API size_t blake3plus_get_hw_threads(void) {
  return blake3plus_get_effective_cpus();
}

BLAKE3_API size_t blake3plus_get_active_workers(void) {
  return atomic_load_explicit(&g_num_workers, memory_order_acquire);
}

static size_t b3p_acquire_free_slot(void) {
  static _Thread_local size_t tl_start = 0;
  size_t start = tl_start;
  for (size_t i = 0; i < B3P_TASK_RING_CAP; i++) {
    size_t idx = (start + i) % B3P_TASK_RING_CAP;
    int exp = B3P_TASK_FREE;
    if (atomic_compare_exchange_strong_explicit(&g_slots[idx].state, &exp, B3P_TASK_ALLOCATED,
                                                memory_order_acq_rel, memory_order_acquire)) {
      tl_start = (idx + 1) % B3P_TASK_RING_CAP;
      return idx;
    }
  }
  return SIZE_MAX;
}

static bool b3p_ring_push(size_t slot_idx) {
  pthread_mutex_lock(&g_ring.lock);
  if (g_ring.count == B3P_TASK_RING_CAP) {
    pthread_mutex_unlock(&g_ring.lock);
    return false;
  }
  g_ring.queue[g_ring.tail] = slot_idx;
  g_ring.tail = (g_ring.tail + 1) % B3P_TASK_RING_CAP;
  g_ring.count++;
  pthread_cond_signal(&g_ring.cv);
  pthread_mutex_unlock(&g_ring.lock);
  return true;
}

static size_t b3p_ring_try_pop(void) {
  pthread_mutex_lock(&g_ring.lock);
  if (g_ring.count == 0) {
    pthread_mutex_unlock(&g_ring.lock);
    return SIZE_MAX;
  }
  size_t slot = g_ring.queue[g_ring.head];
  g_ring.head = (g_ring.head + 1) % B3P_TASK_RING_CAP;
  g_ring.count--;
  pthread_mutex_unlock(&g_ring.lock);
  return slot;
}

static void b3p_execute_slot(size_t slot_idx) {
  b3p_task_slot_t *slot = &g_slots[slot_idx];
  int exp = B3P_TASK_QUEUED;
  if (!atomic_compare_exchange_strong_explicit(&slot->state, &exp, B3P_TASK_RUNNING,
                                              memory_order_acq_rel, memory_order_acquire)) {
    return;
  }
  slot->out_n = blake3_compress_subtree_wide(
      slot->input, slot->input_len, slot->key, slot->chunk_counter,
      slot->flags, slot->cvs, true);

  pthread_mutex_lock(&slot->mtx);
  atomic_store_explicit(&slot->state, B3P_TASK_DONE, memory_order_release);
  pthread_cond_broadcast(&slot->cv);
  pthread_mutex_unlock(&slot->mtx);
}

static sigjmp_buf g_sigbus_envs[B3P_MAX_WORKERS + 1];
static volatile sig_atomic_t g_sigbus_enabled[B3P_MAX_WORKERS + 1] = {0};
static _Thread_local int tl_worker_id = -1;

static void *b3p_worker_loop(void *arg) {
  int worker_id = (int)(intptr_t)arg;
  tl_worker_id = worker_id;
  while (1) {
    pthread_mutex_lock(&g_ring.lock);
    while (g_ring.count == 0 && !g_ring.shutdown) {
      pthread_cond_wait(&g_ring.cv, &g_ring.lock);
    }
    if (g_ring.shutdown && g_ring.count == 0) {
      pthread_mutex_unlock(&g_ring.lock);
      break;
    }
    size_t slot_idx = g_ring.queue[g_ring.head];
    g_ring.head = (g_ring.head + 1) % B3P_TASK_RING_CAP;
    g_ring.count--;
    pthread_mutex_unlock(&g_ring.lock);

    g_sigbus_enabled[worker_id] = 1;
    if (sigsetjmp(g_sigbus_envs[worker_id], 1) != 0) {
      g_sigbus_enabled[worker_id] = 0;
      atomic_store_explicit(&g_slots[slot_idx].state, B3P_TASK_DONE, memory_order_release);
      continue;
    }
    b3p_execute_slot(slot_idx);
    g_sigbus_enabled[worker_id] = 0;
  }
  return NULL;
}

static void b3p_atfork_prepare(void) {
  atomic_store_explicit(&g_pool_fork_active, true, memory_order_release);
  pthread_mutex_lock(&g_pool_lock);
  pthread_mutex_lock(&g_ring.lock);
}

static void b3p_atfork_parent(void) {
  pthread_mutex_unlock(&g_ring.lock);
  pthread_mutex_unlock(&g_pool_lock);
  atomic_store_explicit(&g_pool_fork_active, false, memory_order_release);
}

static void b3p_atfork_child(void) {
  atomic_store_explicit(&g_pool_fork_active, false, memory_order_release);
  atomic_store_explicit(&g_num_workers, 0, memory_order_relaxed);
  pthread_mutex_init(&g_pool_lock, NULL);
  pthread_mutex_init(&g_ring.lock, NULL);
  pthread_cond_init(&g_ring.cv, NULL);
  g_ring.head = 0;
  g_ring.tail = 0;
  g_ring.count = 0;
  g_ring.shutdown = false;
  for (size_t i = 0; i < B3P_TASK_RING_CAP; i++) {
    atomic_init(&g_slots[i].state, B3P_TASK_FREE);
    pthread_mutex_init(&g_slots[i].mtx, NULL);
    pthread_cond_init(&g_slots[i].cv, NULL);
  }
}

static void b3p_register_atfork(void) {
  (void)pthread_atfork(b3p_atfork_prepare, b3p_atfork_parent, b3p_atfork_child);
  atexit(blake3plus_pool_teardown);
}

BLAKE3_API void blake3plus_pool_teardown(void) {
  pthread_mutex_lock(&g_pool_lock);
  size_t current = atomic_load_explicit(&g_num_workers, memory_order_acquire);
  if (current == 0) {
    pthread_mutex_unlock(&g_pool_lock);
    return;
  }

  atomic_store_explicit(&g_num_workers, 0, memory_order_release);

  pthread_mutex_lock(&g_ring.lock);
  g_ring.shutdown = true;
  pthread_cond_broadcast(&g_ring.cv);
  pthread_mutex_unlock(&g_ring.lock);

  for (size_t i = 0; i < current; i++) {
    pthread_join(g_worker_threads[i], NULL);
  }

  pthread_mutex_lock(&g_ring.lock);
  g_ring.head = 0;
  g_ring.tail = 0;
  g_ring.count = 0;
  g_ring.shutdown = false;
  pthread_mutex_unlock(&g_ring.lock);

  pthread_mutex_unlock(&g_pool_lock);
}

static void b3p_ensure_pool_scaled(size_t desired_threads) {
  pthread_once(&g_slots_once, b3p_init_slots);
  pthread_once(&g_atfork_once, b3p_register_atfork);

  size_t hw = blake3plus_get_effective_cpus();
  size_t cap = (desired_threads > 0 && desired_threads < hw) ? desired_threads : hw;
  if (cap > B3P_MAX_WORKERS + 1) {
    cap = B3P_MAX_WORKERS + 1;
  }
  size_t target_workers = (cap > 1) ? (cap - 1) : 0;

  if (atomic_load_explicit(&g_num_workers, memory_order_acquire) >= target_workers) {
    return;
  }

  pthread_mutex_lock(&g_pool_lock);
  size_t current = atomic_load_explicit(&g_num_workers, memory_order_relaxed);
  if (current >= target_workers) {
    pthread_mutex_unlock(&g_pool_lock);
    return;
  }

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  (void)pthread_attr_setstacksize(&attr, BLAKE3PLUS_WORKER_STACK_SIZE);

  for (size_t i = current; i < target_workers; i++) {
    if (pthread_create(&g_worker_threads[i], &attr, b3p_worker_loop, (void *)(intptr_t)i) != 0) {
      target_workers = i;
      break;
    }
  }

  pthread_attr_destroy(&attr);
  atomic_store_explicit(&g_num_workers, target_workers, memory_order_release);
  pthread_mutex_unlock(&g_pool_lock);
}

BLAKE3_PRIVATE void blake3plus_compress_subtree_wide_join_pthread(
    const uint32_t key[8], uint8_t flags, bool use_mt,
    const uint8_t *l_input, size_t l_input_len, uint64_t l_chunk_counter,
    uint8_t *l_cvs, size_t *l_n,
    const uint8_t *r_input, size_t r_input_len, uint64_t r_chunk_counter,
    uint8_t *r_cvs, size_t *r_n) {
  if (!use_mt ||
      r_input_len < BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES ||
      l_input_len < BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES ||
      atomic_load_explicit(&g_num_workers, memory_order_acquire) == 0 ||
      atomic_load_explicit(&g_pool_fork_active, memory_order_acquire)) {
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, use_mt);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, use_mt);
    return;
  }

  size_t slot_idx = b3p_acquire_free_slot();
  if (slot_idx == SIZE_MAX) {
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, false);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, false);
    return;
  }

  b3p_task_slot_t *slot = &g_slots[slot_idx];
  slot->key = key;
  slot->flags = flags;
  slot->input = r_input;
  slot->input_len = r_input_len;
  slot->chunk_counter = r_chunk_counter;
  slot->cvs = r_cvs;
  slot->out_n = 0;
  atomic_store_explicit(&slot->state, B3P_TASK_QUEUED, memory_order_release);

  bool pushed = b3p_ring_push(slot_idx);
  if (!pushed) {
    atomic_store_explicit(&slot->state, B3P_TASK_FREE, memory_order_release);
    *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                        l_chunk_counter, flags, l_cvs, false);
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, false);
    return;
  }

  /* Execute left subtree on current thread */
  *l_n = blake3_compress_subtree_wide(l_input, l_input_len, key,
                                      l_chunk_counter, flags, l_cvs, true);

  /* Now handle right subtree */
  int exp = B3P_TASK_QUEUED;
  if (atomic_compare_exchange_strong_explicit(&slot->state, &exp, B3P_TASK_RUNNING,
                                              memory_order_acq_rel, memory_order_acquire)) {
    /* Worker hasn't picked it up yet! Caller computes it directly */
    *r_n = blake3_compress_subtree_wide(r_input, r_input_len, key,
                                        r_chunk_counter, flags, r_cvs, true);
    atomic_store_explicit(&slot->state, B3P_TASK_FREE, memory_order_release);
  } else {
    /* A worker claimed or is running it. Help other tasks or wait */
    while (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE) {
      size_t other = b3p_ring_try_pop();
      if (other != SIZE_MAX) {
        b3p_execute_slot(other);
      } else {
        int spins = 0;
        while (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE &&
               spins < B3P_MAX_SPIN_ITERS) {
#if defined(__x86_64__) || defined(__i386__)
          __builtin_ia32_pause();
#endif
          spins++;
        }
        if (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE) {
          pthread_mutex_lock(&slot->mtx);
          while (atomic_load_explicit(&slot->state, memory_order_acquire) != B3P_TASK_DONE) {
            pthread_cond_wait(&slot->cv, &slot->mtx);
          }
          pthread_mutex_unlock(&slot->mtx);
        }
      }
    }
    *r_n = slot->out_n;
    atomic_store_explicit(&slot->state, B3P_TASK_FREE, memory_order_release);
  }
}

BLAKE3_API void blake3plus_hasher_update_mt(blake3_hasher *self,
                                            const void *input,
                                            size_t input_len,
                                            size_t num_threads) {
  if (input_len == 0) {
    return;
  }
  size_t hw = blake3plus_get_effective_cpus();
  size_t threads = (num_threads == 0 || num_threads > hw) ? hw : num_threads;
  if (threads <= 1 || input_len < (BLAKE3PLUS_MIN_PARALLEL_SUBTREE_BYTES * 2)) {
    blake3_hasher_update(self, input, input_len);
    return;
  }
  b3p_ensure_pool_scaled(threads);
  blake3_hasher_update_mt_internal(self, input, input_len);
}

BLAKE3_API void blake3plus_hash_buffer_mt(const void *input,
                                          size_t input_len,
                                          uint8_t *out,
                                          size_t out_len,
                                          size_t num_threads) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3plus_hasher_update_mt(&hasher, input, input_len, num_threads);
  blake3_hasher_finalize(&hasher, out, out_len);
  blake3plus_hasher_secure_wipe(&hasher);
}

/* SIGBUS handler to protect against concurrent file truncation during mmap */
static struct sigaction b3p_old_sigbus_sa;
static pthread_once_t b3p_sigbus_once = PTHREAD_ONCE_INIT;

static void b3p_sigbus_handler(int sig, siginfo_t *info, void *ctx) {
  (void)sig; (void)info; (void)ctx;
  int id = tl_worker_id;
  if (id >= 0 && id <= (int)B3P_MAX_WORKERS && g_sigbus_enabled[id]) {
    siglongjmp(g_sigbus_envs[id], 1);
  }
  if (b3p_old_sigbus_sa.sa_sigaction != NULL &&
      (b3p_old_sigbus_sa.sa_flags & SA_SIGINFO)) {
    b3p_old_sigbus_sa.sa_sigaction(sig, info, ctx);
  } else if (b3p_old_sigbus_sa.sa_handler != NULL &&
             b3p_old_sigbus_sa.sa_handler != SIG_DFL &&
             b3p_old_sigbus_sa.sa_handler != SIG_IGN) {
    b3p_old_sigbus_sa.sa_handler(sig);
  } else {
    signal(SIGBUS, SIG_DFL);
    raise(SIGBUS);
  }
}

static void b3p_init_sigbus(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = b3p_sigbus_handler;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGBUS, &sa, &b3p_old_sigbus_sa);
}

/* Double-buffered streaming reader context */
typedef struct {
  int fd;
  uint8_t *buf[2];
  size_t buf_sz;
  ssize_t bytes_read[2];
  int err[2];
  atomic_int ready[2];
  atomic_bool stop;
  pthread_t thread;
} b3p_stream_pipe_t;

static void *b3p_stream_reader_worker(void *arg) {
  b3p_stream_pipe_t *pipe = (b3p_stream_pipe_t *)arg;
  size_t cur = 0;
  while (!atomic_load_explicit(&pipe->stop, memory_order_acquire)) {
    while (atomic_load_explicit(&pipe->ready[cur], memory_order_acquire) == 1 &&
           !atomic_load_explicit(&pipe->stop, memory_order_acquire)) {
      sched_yield();
    }
    if (atomic_load_explicit(&pipe->stop, memory_order_acquire)) {
      break;
    }
    ssize_t n = 0;
    while (1) {
      n = read(pipe->fd, pipe->buf[cur], pipe->buf_sz);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      break;
    }
    pipe->bytes_read[cur] = n;
    pipe->err[cur] = (n < 0) ? errno : 0;
    atomic_store_explicit(&pipe->ready[cur], 1, memory_order_release);
    if (n <= 0) {
      break;
    }
    cur = 1 - cur;
  }
  return NULL;
}

static int __attribute__((noinline)) b3p_safe_mmap_update(
    blake3_hasher *hasher, void *mapped, size_t map_len, size_t num_threads) {
  tl_worker_id = (int)B3P_MAX_WORKERS;
  g_sigbus_enabled[B3P_MAX_WORKERS] = 1;
  if (sigsetjmp(g_sigbus_envs[B3P_MAX_WORKERS], 1) != 0) {
    g_sigbus_enabled[B3P_MAX_WORKERS] = 0;
    return -1;
  }
  blake3plus_hasher_update_mt(hasher, mapped, map_len, num_threads);
  g_sigbus_enabled[B3P_MAX_WORKERS] = 0;
  return 0;
}

static int b3p_hash_fd_internal(int fd,
                                blake3_hasher *hasher,
                                size_t num_threads) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    return -1;
  }

  if (S_ISREG(st.st_mode) && st.st_size == 0) {
    return 0;
  }

  if (S_ISREG(st.st_mode) && st.st_size > 0) {
    pthread_once(&b3p_sigbus_once, b3p_init_sigbus);
    uint64_t remaining = (uint64_t)st.st_size;
    off_t offset = 0;
    bool mmap_ok = true;

    while (remaining > 0) {
      size_t map_len = (remaining > B3P_MAX_MMAP_BYTES)
                           ? (size_t)B3P_MAX_MMAP_BYTES
                           : (size_t)remaining;
      void *mapped = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, offset);
      if (mapped == MAP_FAILED) {
        if (offset == 0) {
          mmap_ok = false;
          break;
        }
        return -1;
      }
      (void)madvise(mapped, map_len, MADV_SEQUENTIAL | MADV_WILLNEED);

      if (b3p_safe_mmap_update(hasher, mapped, map_len, num_threads) != 0) {
        munmap(mapped, map_len);
        mmap_ok = false;
        break;
      }

      munmap(mapped, map_len);
      offset += (off_t)map_len;
      remaining -= map_len;
    }
    if (mmap_ok) {
      return 0;
    }
    (void)lseek(fd, 0, SEEK_SET);
  }

  /* Pipelined double-buffering for pipes, sockets, and non-mmap regular files */
  b3p_stream_pipe_t pipe;
  pipe.fd = fd;
  pipe.buf_sz = B3P_STREAM_BUF_SIZE;
  pipe.buf[0] = (uint8_t *)malloc(pipe.buf_sz);
  pipe.buf[1] = (uint8_t *)malloc(pipe.buf_sz);
  if (!pipe.buf[0] || !pipe.buf[1]) {
    free(pipe.buf[0]);
    free(pipe.buf[1]);
    errno = ENOMEM;
    return -1;
  }
  atomic_init(&pipe.ready[0], 0);
  atomic_init(&pipe.ready[1], 0);
  atomic_init(&pipe.stop, false);

  if (pthread_create(&pipe.thread, NULL, b3p_stream_reader_worker, &pipe) != 0) {
    free(pipe.buf[0]);
    free(pipe.buf[1]);
    errno = EAGAIN;
    return -1;
  }

  size_t cur = 0;
  int stream_rc = 0;
  while (1) {
    while (atomic_load_explicit(&pipe.ready[cur], memory_order_acquire) == 0) {
      sched_yield();
    }
    if (pipe.bytes_read[cur] < 0) {
      errno = pipe.err[cur];
      stream_rc = -1;
      break;
    }
    if (pipe.bytes_read[cur] == 0) {
      break;
    }
    blake3plus_hasher_update_mt(hasher, pipe.buf[cur], (size_t)pipe.bytes_read[cur], num_threads);
    atomic_store_explicit(&pipe.ready[cur], 0, memory_order_release);
    cur = 1 - cur;
  }

  atomic_store_explicit(&pipe.stop, true, memory_order_release);
  pthread_join(pipe.thread, NULL);
  blake3plus_secure_zero(pipe.buf[0], pipe.buf_sz);
  blake3plus_secure_zero(pipe.buf[1], pipe.buf_sz);
  free(pipe.buf[0]);
  free(pipe.buf[1]);
  return stream_rc;
}

BLAKE3_API int blake3plus_hasher_hash_fd(blake3_hasher *hasher,
                                         int fd,
                                         size_t num_threads) {
  if (!hasher || fd < 0) {
    errno = EINVAL;
    return -1;
  }
  return b3p_hash_fd_internal(fd, hasher, num_threads);
}

BLAKE3_API int blake3plus_hash_fd(int fd,
                                  uint8_t *out,
                                  size_t out_len,
                                  size_t num_threads) {
  if (fd < 0 || !out || out_len == 0) {
    errno = EINVAL;
    return -1;
  }

  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  int rc = b3p_hash_fd_internal(fd, &hasher, num_threads);
  if (rc != 0) {
    int saved_errno = errno;
    blake3plus_hasher_secure_wipe(&hasher);
    errno = saved_errno;
    return -1;
  }

  blake3_hasher_finalize(&hasher, out, out_len);
  blake3plus_hasher_secure_wipe(&hasher);
  return 0;
}

BLAKE3_API int blake3plus_hash_file_mmap(const char *filepath,
                                         uint8_t *out,
                                         size_t out_len,
                                         size_t num_threads) {
  if (!filepath) {
    errno = EINVAL;
    return -1;
  }

  int fd = open(filepath, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }

  int rc = blake3plus_hash_fd(fd, out, out_len, num_threads);
  int saved_errno = errno;
  close(fd);
  if (rc != 0) {
    errno = saved_errno;
    return -1;
  }
  return 0;
}

BLAKE3_API void blake3plus_secure_zero(void *ptr, size_t len) {
  if (!ptr || len == 0) {
    return;
  }
  volatile uint8_t *vptr = (volatile uint8_t *)ptr;
  for (size_t i = 0; i < len; i++) {
    vptr[i] = 0;
  }
#if defined(__GNUC__) || defined(__clang__)
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
}

BLAKE3_API void blake3plus_hasher_secure_wipe(blake3_hasher *self) {
  if (!self) {
    return;
  }
  blake3plus_secure_zero(self, sizeof(blake3_hasher));
}

BLAKE3_API int blake3plus_constant_time_eq(const uint8_t *a,
                                           const uint8_t *b,
                                           size_t len) {
  if (!a || !b) {
    return -1;
  }
  volatile uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= (uint8_t)(a[i] ^ b[i]);
  }
  uint32_t d = diff;
  return (int)((0U - d) >> 31) ? -1 : 0;
}

BLAKE3_API void blake3plus_keyed_mac_sign(const uint8_t key[BLAKE3_KEY_LEN],
                                          const void *input,
                                          size_t input_len,
                                          uint8_t *mac_out,
                                          size_t mac_len,
                                          size_t num_threads) {
  blake3_hasher hasher;
  blake3_hasher_init_keyed(&hasher, key);
  blake3plus_hasher_update_mt(&hasher, input, input_len, num_threads);
  blake3_hasher_finalize(&hasher, mac_out, mac_len);
  blake3plus_hasher_secure_wipe(&hasher);
}

BLAKE3_API int blake3plus_keyed_mac_verify(const uint8_t key[BLAKE3_KEY_LEN],
                                           const void *input,
                                           size_t input_len,
                                           const uint8_t *expected_mac,
                                           size_t mac_len,
                                           size_t num_threads) {
  if (!key || !expected_mac || mac_len == 0) {
    return -1;
  }

  uint8_t stack_mac[64];
  uint8_t *computed_mac = stack_mac;
  if (mac_len > sizeof(stack_mac)) {
    computed_mac = (uint8_t *)malloc(mac_len);
    if (!computed_mac) {
      return -1;
    }
  }

  blake3plus_keyed_mac_sign(key, input, input_len, computed_mac, mac_len,
                            num_threads);
  int rc = blake3plus_constant_time_eq(computed_mac, expected_mac, mac_len);

  blake3plus_secure_zero(computed_mac, mac_len);
  if (computed_mac != stack_mac) {
    free(computed_mac);
  }
  return rc;
}

BLAKE3_API void blake3plus_domain_hash(const char *domain_context,
                                       const void *input,
                                       size_t input_len,
                                       uint8_t *out,
                                       size_t out_len,
                                       size_t num_threads) {
  blake3_hasher hasher;
  blake3_hasher_init_derive_key(&hasher, domain_context ? domain_context : "");
  blake3plus_hasher_update_mt(&hasher, input, input_len, num_threads);
  blake3_hasher_finalize(&hasher, out, out_len);
  blake3plus_hasher_secure_wipe(&hasher);
}

/* --- End: c/blake3plus.c --- */
