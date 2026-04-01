#include <stddef.h>

#include "api.h"
#include "inner.h"

int tidecoin_falcon1024_pubkey_from_sk(const uint8_t *sk, size_t sklen,
                                       uint8_t *pk, size_t pklen)
{
    if (sklen != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES ||
        pklen != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return -1;
    }

    int8_t f[1024];
    int8_t g[1024];
    uint16_t h[1024];
    union {
        uint8_t b[2 * 1024 * sizeof(uint16_t)];
        uint16_t dummy_u16;
    } tmp;

    size_t u = 1;
    size_t v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(
        f, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10],
        sk + u, sklen - u);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_decode(
        g, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10],
        sk + u, sklen - u);
    if (v == 0) {
        return -1;
    }

    if (!PQCLEAN_FALCON1024_CLEAN_compute_public(h, f, g, 10, tmp.b)) {
        return -1;
    }

    pk[0] = 0x00 + 10;
    v = PQCLEAN_FALCON1024_CLEAN_modq_encode(
        pk + 1, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1,
        h, 10);
    if (v != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }

    return 0;
}


int tidecoin_falcon1024_keypair_from_seed(uint8_t *pk, size_t pklen,
                                          uint8_t *sk, size_t sklen,
                                          const uint8_t *seed, size_t seedlen)
{
    union {
        uint8_t b[FALCON_KEYGEN_TEMP_10];
        uint64_t dummy_u64;
        fpr dummy_fpr;
    } tmp;
    int8_t f[1024], g[1024], F[1024];
    uint16_t h[1024];
    inner_shake256_context rng;
    size_t u, v;

    if (pklen != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        sklen != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES ||
        seedlen != 48) {
        return -1;
    }

    inner_shake256_init(&rng);
    inner_shake256_inject(&rng, seed, seedlen);
    inner_shake256_flip(&rng);
    PQCLEAN_FALCON1024_CLEAN_keygen(&rng, f, g, F, NULL, h, 10, tmp.b);
    inner_shake256_ctx_release(&rng);

    sk[0] = 0x50 + 10;
    u = 1;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        f, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        g, 10, PQCLEAN_FALCON1024_CLEAN_max_fg_bits[10]);
    if (v == 0) {
        return -1;
    }
    u += v;
    v = PQCLEAN_FALCON1024_CLEAN_trim_i8_encode(
        sk + u, PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES - u,
        F, 10, PQCLEAN_FALCON1024_CLEAN_max_FG_bits[10]);
    if (v == 0) {
        return -1;
    }
    u += v;
    if (u != PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES) {
        return -1;
    }

    pk[0] = 0x00 + 10;
    v = PQCLEAN_FALCON1024_CLEAN_modq_encode(
        pk + 1, PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1,
        h, 10);
    if (v != PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES - 1) {
        return -1;
    }

    return 0;
}
