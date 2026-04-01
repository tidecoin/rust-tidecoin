#include <stddef.h>
#include <string.h>

#include "fips202.h"
#include "packing.h"

int tidecoin_mldsa65_pubkey_from_sk(const uint8_t *sk, size_t sklen,
                                    uint8_t *pk, size_t pklen)
{
    if (sklen != PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES ||
        pklen != PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES) {
        return -1;
    }

    uint8_t rho[SEEDBYTES];
    uint8_t tr[TRBYTES];
    uint8_t key[SEEDBYTES];
    polyvecl mat[K];
    polyvecl s1;
    polyvecl s1hat;
    polyveck s2;
    polyveck t0;
    polyveck t1;

    PQCLEAN_MLDSA65_CLEAN_unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);

    s1hat = s1;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&t1, &t1, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_MLDSA65_CLEAN_pack_pk(pk, rho, &t1);
    return 0;
}

int tidecoin_mldsa65_keypair_from_seed(uint8_t *pk, size_t pklen,
                                       uint8_t *sk, size_t sklen,
                                       const uint8_t *seed, size_t seedlen)
{
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    uint8_t tr[TRBYTES];
    const uint8_t *rho, *rhoprime, *key;
    polyvecl mat[K];
    polyvecl s1, s1hat;
    polyveck s2, t1, t0;

    if (pklen != PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        sklen != PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES ||
        seedlen != SEEDBYTES) {
        return -1;
    }

    memcpy(seedbuf, seed, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key = rhoprime + CRHBYTES;

    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_expand(mat, rho);
    PQCLEAN_MLDSA65_CLEAN_polyvecl_uniform_eta(&s1, rhoprime, 0);
    PQCLEAN_MLDSA65_CLEAN_polyveck_uniform_eta(&s2, rhoprime, L);

    s1hat = s1;
    PQCLEAN_MLDSA65_CLEAN_polyvecl_ntt(&s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    PQCLEAN_MLDSA65_CLEAN_polyveck_reduce(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_invntt_tomont(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_add(&t1, &t1, &s2);
    PQCLEAN_MLDSA65_CLEAN_polyveck_caddq(&t1);
    PQCLEAN_MLDSA65_CLEAN_polyveck_power2round(&t1, &t0, &t1);
    PQCLEAN_MLDSA65_CLEAN_pack_pk(pk, rho, &t1);

    shake256(tr, TRBYTES, pk, PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES);
    PQCLEAN_MLDSA65_CLEAN_pack_sk(sk, rho, tr, key, &t0, &s1, &s2);
    return 0;
}
