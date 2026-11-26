/*
 * Argon2 AVX2 optimized BlaMka round functions
 *
 * Based on Argon2 reference source code package
 * Copyright 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, Samuel Neves
 *
 * Optimized for AVX2 (256-bit SIMD)
 * Adapted for Rincoin project
 */

#ifndef BLAMKA_ROUND_AVX2_H
#define BLAMKA_ROUND_AVX2_H

#include "blake2-impl.h"

#if defined(__AVX2__)

#include <immintrin.h>

/* Rotation macros optimized for AVX2 */
#define rotr32_avx2(x) _mm256_shuffle_epi32((x), _MM_SHUFFLE(2, 3, 0, 1))

#define rotr24_avx2(x) _mm256_shuffle_epi8((x), \
    _mm256_setr_epi8( \
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, \
        3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10))

#define rotr16_avx2(x) _mm256_shuffle_epi8((x), \
    _mm256_setr_epi8( \
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, \
        2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9))

#define rotr63_avx2(x) _mm256_xor_si256(_mm256_srli_epi64((x), 63), _mm256_add_epi64((x), (x)))

/*
 * BlaMka G function for AVX2
 * Processes 4 64-bit values in parallel using 256-bit registers
 */
#define G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i ml; \
        \
        ml = _mm256_mul_epu32(A0, B0); \
        ml = _mm256_add_epi64(ml, ml); \
        A0 = _mm256_add_epi64(A0, _mm256_add_epi64(B0, ml)); \
        D0 = _mm256_xor_si256(D0, A0); \
        D0 = rotr32_avx2(D0); \
        \
        ml = _mm256_mul_epu32(C0, D0); \
        ml = _mm256_add_epi64(ml, ml); \
        C0 = _mm256_add_epi64(C0, _mm256_add_epi64(D0, ml)); \
        B0 = _mm256_xor_si256(B0, C0); \
        B0 = rotr24_avx2(B0); \
        \
        ml = _mm256_mul_epu32(A1, B1); \
        ml = _mm256_add_epi64(ml, ml); \
        A1 = _mm256_add_epi64(A1, _mm256_add_epi64(B1, ml)); \
        D1 = _mm256_xor_si256(D1, A1); \
        D1 = rotr32_avx2(D1); \
        \
        ml = _mm256_mul_epu32(C1, D1); \
        ml = _mm256_add_epi64(ml, ml); \
        C1 = _mm256_add_epi64(C1, _mm256_add_epi64(D1, ml)); \
        B1 = _mm256_xor_si256(B1, C1); \
        B1 = rotr24_avx2(B1); \
    } while ((void)0, 0)

#define G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i ml; \
        \
        ml = _mm256_mul_epu32(A0, B0); \
        ml = _mm256_add_epi64(ml, ml); \
        A0 = _mm256_add_epi64(A0, _mm256_add_epi64(B0, ml)); \
        D0 = _mm256_xor_si256(D0, A0); \
        D0 = rotr16_avx2(D0); \
        \
        ml = _mm256_mul_epu32(C0, D0); \
        ml = _mm256_add_epi64(ml, ml); \
        C0 = _mm256_add_epi64(C0, _mm256_add_epi64(D0, ml)); \
        B0 = _mm256_xor_si256(B0, C0); \
        B0 = rotr63_avx2(B0); \
        \
        ml = _mm256_mul_epu32(A1, B1); \
        ml = _mm256_add_epi64(ml, ml); \
        A1 = _mm256_add_epi64(A1, _mm256_add_epi64(B1, ml)); \
        D1 = _mm256_xor_si256(D1, A1); \
        D1 = rotr16_avx2(D1); \
        \
        ml = _mm256_mul_epu32(C1, D1); \
        ml = _mm256_add_epi64(ml, ml); \
        C1 = _mm256_add_epi64(C1, _mm256_add_epi64(D1, ml)); \
        B1 = _mm256_xor_si256(B1, C1); \
        B1 = rotr63_avx2(B1); \
    } while ((void)0, 0)

/*
 * Diagonal shuffles for BlaMka
 * Used to rearrange data between column and diagonal operations
 */
#define DIAGONALIZE_AVX2(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        __m256i t0 = _mm256_permute4x64_epi64(B0, _MM_SHUFFLE(0, 3, 2, 1)); \
        __m256i t1 = _mm256_permute4x64_epi64(B1, _MM_SHUFFLE(0, 3, 2, 1)); \
        B0 = t0; \
        B1 = t1; \
        \
        t0 = _mm256_permute4x64_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        t1 = _mm256_permute4x64_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        C0 = t0; \
        C1 = t1; \
        \
        t0 = _mm256_permute4x64_epi64(D0, _MM_SHUFFLE(2, 1, 0, 3)); \
        t1 = _mm256_permute4x64_epi64(D1, _MM_SHUFFLE(2, 1, 0, 3)); \
        D0 = t0; \
        D1 = t1; \
    } while ((void)0, 0)

#define UNDIAGONALIZE_AVX2(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        __m256i t0 = _mm256_permute4x64_epi64(B0, _MM_SHUFFLE(2, 1, 0, 3)); \
        __m256i t1 = _mm256_permute4x64_epi64(B1, _MM_SHUFFLE(2, 1, 0, 3)); \
        B0 = t0; \
        B1 = t1; \
        \
        t0 = _mm256_permute4x64_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        t1 = _mm256_permute4x64_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        C0 = t0; \
        C1 = t1; \
        \
        t0 = _mm256_permute4x64_epi64(D0, _MM_SHUFFLE(0, 3, 2, 1)); \
        t1 = _mm256_permute4x64_epi64(D1, _MM_SHUFFLE(0, 3, 2, 1)); \
        D0 = t0; \
        D1 = t1; \
    } while ((void)0, 0)

/*
 * Complete BlaMka round macros for AVX2
 * BLAKE2_ROUND_1: Column operations
 * BLAKE2_ROUND_2: Diagonal operations
 */
#define BLAKE2_ROUND_1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1); \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1); \
        DIAGONALIZE_AVX2(A0, B0, C0, D0, A1, B1, C1, D1); \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1); \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1); \
        UNDIAGONALIZE_AVX2(A0, B0, C0, D0, A1, B1, C1, D1); \
    } while ((void)0, 0)

#define BLAKE2_ROUND_2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    BLAKE2_ROUND_1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1)

/* Number of 256-bit words in an Argon2 block (1024 bytes / 32 bytes = 32) */
#define ARGON2_HWORDS_IN_BLOCK 32

#endif /* __AVX2__ */

#endif /* BLAMKA_ROUND_AVX2_H */
