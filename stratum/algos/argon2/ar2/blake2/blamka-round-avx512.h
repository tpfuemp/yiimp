/*
 * Argon2 AVX-512 optimized BlaMka round functions
 *
 * Based on Argon2 reference source code package
 * Copyright 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, Samuel Neves
 *
 * Optimized for AVX-512 (512-bit SIMD)
 * Adapted for Rincoin project
 */

#ifndef BLAMKA_ROUND_AVX512_H
#define BLAMKA_ROUND_AVX512_H

#include "blake2-impl.h"

#if defined(__AVX512F__) && defined(__AVX512DQ__)

#include <immintrin.h>

/* Rotation macros optimized for AVX-512 */
#define rotr32_avx512(x) _mm512_ror_epi64((x), 32)
#define rotr24_avx512(x) _mm512_ror_epi64((x), 24)
#define rotr16_avx512(x) _mm512_ror_epi64((x), 16)
#define rotr63_avx512(x) _mm512_ror_epi64((x), 63)

/*
 * BlaMka fBlaMka function for AVX-512: 2*a*b + a + b
 * Uses 512-bit multiplication
 */
static BLAKE2_INLINE __m512i fBlaMka_avx512(__m512i x, __m512i y) {
    const __m512i z = _mm512_mul_epu32(x, y);
    return _mm512_add_epi64(_mm512_add_epi64(x, y), _mm512_add_epi64(z, z));
}

/*
 * BlaMka G function for AVX-512
 * Processes 8 64-bit values in parallel using 512-bit registers
 */
#define G1_AVX512(A, B, C, D) \
    do { \
        A = fBlaMka_avx512(A, B); \
        D = _mm512_xor_si512(D, A); \
        D = rotr32_avx512(D); \
        \
        C = fBlaMka_avx512(C, D); \
        B = _mm512_xor_si512(B, C); \
        B = rotr24_avx512(B); \
    } while ((void)0, 0)

#define G2_AVX512(A, B, C, D) \
    do { \
        A = fBlaMka_avx512(A, B); \
        D = _mm512_xor_si512(D, A); \
        D = rotr16_avx512(D); \
        \
        C = fBlaMka_avx512(C, D); \
        B = _mm512_xor_si512(B, C); \
        B = rotr63_avx512(B); \
    } while ((void)0, 0)

/*
 * Diagonal shuffles for AVX-512 BlaMka
 */
#define DIAGONALIZE_AVX512(A, B, C, D) \
    do { \
        B = _mm512_permutex_epi64(B, _MM_SHUFFLE(0, 3, 2, 1)); \
        C = _mm512_permutex_epi64(C, _MM_SHUFFLE(1, 0, 3, 2)); \
        D = _mm512_permutex_epi64(D, _MM_SHUFFLE(2, 1, 0, 3)); \
    } while ((void)0, 0)

#define UNDIAGONALIZE_AVX512(A, B, C, D) \
    do { \
        B = _mm512_permutex_epi64(B, _MM_SHUFFLE(2, 1, 0, 3)); \
        C = _mm512_permutex_epi64(C, _MM_SHUFFLE(1, 0, 3, 2)); \
        D = _mm512_permutex_epi64(D, _MM_SHUFFLE(0, 3, 2, 1)); \
    } while ((void)0, 0)

/*
 * Complete BlaMka round macro for AVX-512
 */
#define BLAKE2_ROUND_AVX512(A, B, C, D) \
    do { \
        G1_AVX512(A, B, C, D); \
        G2_AVX512(A, B, C, D); \
        DIAGONALIZE_AVX512(A, B, C, D); \
        G1_AVX512(A, B, C, D); \
        G2_AVX512(A, B, C, D); \
        UNDIAGONALIZE_AVX512(A, B, C, D); \
    } while ((void)0, 0)

/* Number of 512-bit words in an Argon2 block (1024 bytes / 64 bytes = 16) */
#define ARGON2_512BIT_WORDS_IN_BLOCK 16

#endif /* __AVX512F__ && __AVX512DQ__ */

#endif /* BLAMKA_ROUND_AVX512_H */
