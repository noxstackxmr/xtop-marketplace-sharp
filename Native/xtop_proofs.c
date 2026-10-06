/* Experimental XTOP proof primitives. Compositions follow Monero v0.18.5.1
 * crypto.cpp / rctOps.cpp; upstream arithmetic and hashing are unchanged.
 * Copyright notices and redistribution terms: vendor/monero/LICENSE.
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

static const unsigned char identity[32] = {1};
static const unsigned char order[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
static const unsigned char H[32] = {
    0x8b,0x65,0x59,0x70,0x15,0x37,0x99,0xaf,0x2a,0xea,0xdc,0x9f,0xf1,0xad,0xd0,0xea,
    0x6c,0x72,0x51,0xd5,0x41,0x54,0xcf,0xa9,0x2c,0x17,0x3a,0x0d,0xd3,0x9c,0x1f,0x94};

static void wipe(void *p, size_t n) {
    volatile unsigned char *b = (volatile unsigned char *)p;
    while (n--) *b++ = 0;
}
static void hs(const void *p, size_t n, unsigned char *s) {
    cn_fast_hash(p, n, (char *)s); sc_reduce32(s);
}
static int secret_ok(const unsigned char *s) {
    return s && sc_check(s) == 0 && sc_isnonzero(s);
}
static int decode(const unsigned char *encoded, ge_p3 *point) {
    unsigned char canonical[32], subgroup[32];
    ge_p2 product;
    if (!encoded || ge_frombytes_vartime(point, encoded) != 0) return 0;
    ge_p3_tobytes(canonical, point);
    if (memcmp(canonical, encoded, 32) || !memcmp(encoded, identity, 32)) return 0;
    ge_scalarmult(&product, order, point);
    ge_tobytes(subgroup, &product);
    return memcmp(subgroup, identity, 32) == 0;
}
static void base_mul(const unsigned char *s, unsigned char *p) {
    ge_p3 point; ge_scalarmult_base(&point, s); ge_p3_tobytes(p, &point);
    wipe(&point, sizeof(point));
}
static void point_mul(const ge_p3 *point, const unsigned char *s, unsigned char *p) {
    ge_p2 product; ge_scalarmult(&product, s, point); ge_tobytes(p, &product);
    wipe(&product, sizeof(product));
}

EXPORT int xtop_point_is_valid(const unsigned char *p) { ge_p3 point; return decode(p, &point); }
EXPORT void xtop_fast_hash(const unsigned char *data, size_t length, unsigned char *hash) {
    cn_fast_hash(data, length, (char *)hash);
}
EXPORT int xtop_scalar_is_canonical(const unsigned char *s) { return sc_check(s) == 0; }
EXPORT void xtop_hash_to_scalar(const unsigned char *data, size_t length, unsigned char *s) { hs(data,length,s); }
EXPORT void xtop_scalar_reduce32(const unsigned char *input, unsigned char *result) {
    memcpy(result, input, 32); sc_reduce32(result);
}
EXPORT int xtop_point_multiply(const unsigned char *p, const unsigned char *s, unsigned char *result) {
    ge_p3 point;
    if (sc_check(s) || !decode(p, &point)) return 0;
    point_mul(&point, s, result); return 1;
}
EXPORT void xtop_hash_to_point(const unsigned char *p, unsigned char *result) {
    unsigned char hash[32]; ge_p2 point; ge_p1p1 multiplied; ge_p3 final;
    cn_fast_hash(p, 32, (char *)hash); ge_fromfe_frombytes_vartime(&point, hash);
    ge_mul8(&multiplied, &point); ge_p1p1_to_p3(&final, &multiplied);
    ge_p3_tobytes(result, &final);
}
EXPORT int xtop_commitment(const unsigned char *mask, uint64_t amount, unsigned char *result) {
    unsigned char value[32] = {0}; ge_p3 h; ge_p2 point;
    if (sc_check(mask) || !decode(H, &h)) return 0;
    for (size_t i=0;i<8;i++) { value[i]=(unsigned char)amount; amount >>= 8; }
    ge_double_scalarmult_base_vartime(&point, value, &h, mask);
    ge_tobytes(result, &point); wipe(&point,sizeof(point)); return 1;
}

/* Standard-address TXPROOF_V2, B absent: c || s, 64 bytes. */
static void dleq_prefix(unsigned char *buffer, const unsigned char *message,
    const unsigned char *R, const unsigned char *A, const unsigned char *D) {
    memset(buffer,0,256); memcpy(buffer,message,32); memcpy(buffer+32,D,32);
    cn_fast_hash("TXPROOF_V2",10,(char *)(buffer+128));
    memcpy(buffer+160,R,32); memcpy(buffer+192,A,32);
}
EXPORT int xtop_dleq_create(const unsigned char *message, const unsigned char *R,
    const unsigned char *A, const unsigned char *D, const unsigned char *secret,
    const unsigned char *nonce, unsigned char *proof) {
    unsigned char buffer[256], expected[32]; ge_p3 a,r,d;
    if (!secret_ok(secret) || !secret_ok(nonce) || !decode(A,&a) || !decode(R,&r) || !decode(D,&d)) return 0;
    base_mul(secret,expected); if (memcmp(expected,R,32)) return 0;
    point_mul(&a,secret,expected); if (memcmp(expected,D,32)) return 0;
    dleq_prefix(buffer,message,R,A,D);
    base_mul(nonce,buffer+64); point_mul(&a,nonce,buffer+96);
    hs(buffer,sizeof(buffer),proof); sc_mulsub(proof+32,proof,secret,nonce);
    wipe(buffer,sizeof(buffer)); wipe(expected,sizeof(expected)); return 1;
}
EXPORT int xtop_dleq_verify(const unsigned char *message, const unsigned char *R,
    const unsigned char *A, const unsigned char *D, const unsigned char *proof) {
    unsigned char buffer[256], challenge[32]; ge_p3 r,a,d;
    ge_p2 x; ge_dsmp d_pre;
    if (sc_check(proof) || sc_check(proof+32) || !decode(R,&r) || !decode(A,&a) || !decode(D,&d)) return 0;
    dleq_prefix(buffer,message,R,A,D);
    ge_double_scalarmult_base_vartime(&x,proof,&r,proof+32);
    ge_tobytes(buffer+64,&x);
    ge_dsm_precomp(d_pre,&d);
    ge_double_scalarmult_precomp_vartime(&x,proof+32,&a,proof,d_pre);
    ge_tobytes(buffer+96,&x);
    hs(buffer,sizeof(buffer),challenge);
    return memcmp(challenge,proof,32)==0;
}
EXPORT int xtop_signature_create(const unsigned char *message, const unsigned char *public_key,
    const unsigned char *secret, const unsigned char *nonce, unsigned char *signature) {
    unsigned char buffer[96], expected[32]; ge_p3 point;
    if (!secret_ok(secret) || !secret_ok(nonce) || !decode(public_key,&point)) return 0;
    base_mul(secret,expected); if (memcmp(expected,public_key,32)) return 0;
    memcpy(buffer,message,32); memcpy(buffer+32,public_key,32); base_mul(nonce,buffer+64);
    hs(buffer,sizeof(buffer),signature); sc_mulsub(signature+32,signature,secret,nonce);
    wipe(buffer,sizeof(buffer)); wipe(expected,sizeof(expected));
    return sc_isnonzero(signature) && sc_isnonzero(signature+32);
}
EXPORT int xtop_signature_verify(const unsigned char *message, const unsigned char *public_key,
    const unsigned char *signature) {
    unsigned char buffer[96], challenge[32]; ge_p3 point; ge_p2 commitment;
    if (sc_check(signature) || sc_check(signature+32) || !sc_isnonzero(signature) || !decode(public_key,&point)) return 0;
    memcpy(buffer,message,32); memcpy(buffer+32,public_key,32);
    ge_double_scalarmult_base_vartime(&commitment,signature,&point,signature+32);
    ge_tobytes(buffer+64,&commitment);
    if (!memcmp(buffer+64,identity,32)) return 0;
    hs(buffer,sizeof(buffer),challenge);
    return memcmp(challenge,signature,32)==0;
}
