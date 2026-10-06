/*
 * Experimental C ABI for the output-key operations in Monero v0.18.5.1.
 * The compositions below follow src/crypto/crypto.cpp in that release.
 * Arithmetic and Keccak are provided by the unmodified vendored Monero code.
 * This is not a transaction builder or an XTOP proof implementation.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "crypto-ops.h"
#include "hash-ops.h"

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

static void clear_bytes(void *data, size_t length) {
    volatile unsigned char *bytes = (volatile unsigned char *)data;
    while (length--) *bytes++ = 0;
}

EXPORT int xtop_secret_is_valid(const unsigned char *secret) {
    return secret && sc_check(secret) == 0 && sc_isnonzero(secret) != 0;
}

EXPORT int xtop_secret_to_public(const unsigned char *secret, unsigned char *result) {
    ge_p3 point;
    if (!result || !xtop_secret_is_valid(secret)) return 0;
    ge_scalarmult_base(&point, secret);
    ge_p3_tobytes(result, &point);
    clear_bytes(&point, sizeof(point));
    return 1;
}

EXPORT int xtop_generate_derivation(
    const unsigned char *public_key, const unsigned char *secret, unsigned char *result) {
    ge_p3 point;
    ge_p2 product;
    ge_p1p1 multiplied;
    if (!public_key || !result || !xtop_secret_is_valid(secret)) return 0;
    if (ge_frombytes_vartime(&point, public_key) != 0) return 0;
    ge_scalarmult(&product, secret, &point);
    ge_mul8(&multiplied, &product);
    ge_p1p1_to_p2(&product, &multiplied);
    ge_tobytes(result, &product);
    clear_bytes(&point, sizeof(point));
    clear_bytes(&product, sizeof(product));
    clear_bytes(&multiplied, sizeof(multiplied));
    return 1;
}

static void derivation_to_scalar(
    const unsigned char *derivation, uint64_t index, unsigned char *scalar) {
    unsigned char buffer[32 + 10];
    size_t length = 32;
    memcpy(buffer, derivation, 32);
    do {
        unsigned char next = (unsigned char)(index & 0x7f);
        index >>= 7;
        if (index) next |= 0x80;
        buffer[length++] = next;
    } while (index);
    cn_fast_hash(buffer, length, (char *)scalar);
    sc_reduce32(scalar);
    clear_bytes(buffer, sizeof(buffer));
}

EXPORT int xtop_derive_public(
    const unsigned char *derivation, uint64_t index,
    const unsigned char *spend_public, unsigned char *result) {
    unsigned char scalar[32];
    ge_p3 base, added;
    ge_cached cached;
    ge_p1p1 sum;
    ge_p2 point;
    if (!derivation || !spend_public || !result) return 0;
    if (ge_frombytes_vartime(&base, spend_public) != 0) return 0;
    derivation_to_scalar(derivation, index, scalar);
    ge_scalarmult_base(&added, scalar);
    ge_p3_to_cached(&cached, &added);
    ge_add(&sum, &base, &cached);
    ge_p1p1_to_p2(&point, &sum);
    ge_tobytes(result, &point);
    clear_bytes(scalar, sizeof(scalar));
    clear_bytes(&added, sizeof(added));
    clear_bytes(&cached, sizeof(cached));
    clear_bytes(&sum, sizeof(sum));
    clear_bytes(&point, sizeof(point));
    return 1;
}

EXPORT int xtop_derive_secret(
    const unsigned char *derivation, uint64_t index,
    const unsigned char *spend_secret, unsigned char *result) {
    unsigned char scalar[32];
    if (!derivation || !result || !xtop_secret_is_valid(spend_secret)) return 0;
    derivation_to_scalar(derivation, index, scalar);
    sc_add(result, spend_secret, scalar);
    clear_bytes(scalar, sizeof(scalar));
    return 1;
}

EXPORT int xtop_generate_key_image(
    const unsigned char *public_key, const unsigned char *secret, unsigned char *result) {
    unsigned char hash[32];
    ge_p2 hashed, product;
    ge_p1p1 multiplied;
    ge_p3 point;
    if (!public_key || !result || !xtop_secret_is_valid(secret)) return 0;
    cn_fast_hash(public_key, 32, (char *)hash);
    ge_fromfe_frombytes_vartime(&hashed, hash);
    ge_mul8(&multiplied, &hashed);
    ge_p1p1_to_p3(&point, &multiplied);
    ge_scalarmult(&product, secret, &point);
    ge_tobytes(result, &product);
    clear_bytes(hash, sizeof(hash));
    clear_bytes(&point, sizeof(point));
    clear_bytes(&product, sizeof(product));
    return 1;
}
