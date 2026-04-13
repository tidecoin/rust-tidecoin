#include <stddef.h>
#include <stdint.h>

int tidecoin_node_check_transaction(const char* tx_hex)
{
    (void)tx_hex;
    return -1;
}

int64_t tidecoin_node_pq_p2wpkh_input_vsize(size_t sig_len, size_t pubkey_len)
{
    (void)sig_len;
    (void)pubkey_len;
    return -1;
}

int64_t tidecoin_node_pq_p2sh_p2wpkh_input_vsize(size_t sig_len, size_t pubkey_len)
{
    (void)sig_len;
    (void)pubkey_len;
    return -1;
}

int tidecoin_node_pq_keygen_from_seed(
    uint8_t scheme_prefix,
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* pk_out,
    size_t pk_len,
    uint8_t* sk_out,
    size_t sk_len)
{
    (void)scheme_prefix;
    (void)seed;
    (void)seed_len;
    (void)pk_out;
    (void)pk_len;
    (void)sk_out;
    (void)sk_len;
    return -1;
}

int tidecoin_node_pqhd_keygen_from_stream_key(
    uint8_t scheme_prefix,
    const uint8_t* stream_key,
    size_t stream_key_len,
    uint8_t* pk_out,
    size_t pk_len,
    uint8_t* sk_out,
    size_t sk_len)
{
    (void)scheme_prefix;
    (void)stream_key;
    (void)stream_key_len;
    (void)pk_out;
    (void)pk_len;
    (void)sk_out;
    (void)sk_len;
    return -1;
}

int tidecoin_node_pq_compute_public_key(
    uint8_t scheme_prefix,
    const uint8_t* sk,
    size_t sk_len,
    uint8_t* pk_out,
    size_t pk_len)
{
    (void)scheme_prefix;
    (void)sk;
    (void)sk_len;
    (void)pk_out;
    (void)pk_len;
    return -1;
}

int tidecoin_node_pq_sign_message(
    uint8_t scheme_prefix,
    const uint8_t* msg,
    size_t msg_len,
    const uint8_t* sk,
    size_t sk_len,
    int legacy_mode,
    uint8_t* sig_out,
    size_t* sig_len)
{
    (void)scheme_prefix;
    (void)msg;
    (void)msg_len;
    (void)sk;
    (void)sk_len;
    (void)legacy_mode;
    (void)sig_out;
    if (sig_len != NULL) {
        *sig_len = 0;
    }
    return -1;
}

int tidecoin_node_pq_verify_message(
    uint8_t scheme_prefix,
    const uint8_t* msg,
    size_t msg_len,
    const uint8_t* sig,
    size_t sig_len,
    const uint8_t* pk,
    size_t pk_len,
    int legacy_mode)
{
    (void)scheme_prefix;
    (void)msg;
    (void)msg_len;
    (void)sig;
    (void)sig_len;
    (void)pk;
    (void)pk_len;
    (void)legacy_mode;
    return -1;
}

int tidecoin_node_mlkem512_keypair_from_coins(
    const uint8_t* coins,
    size_t coins_len,
    uint8_t* pk_out,
    size_t pk_len,
    uint8_t* sk_out,
    size_t sk_len)
{
    (void)coins;
    (void)coins_len;
    (void)pk_out;
    (void)pk_len;
    (void)sk_out;
    (void)sk_len;
    return -1;
}

int tidecoin_node_mlkem512_encaps_deterministic(
    const uint8_t* pk,
    size_t pk_len,
    const uint8_t* coins,
    size_t coins_len,
    uint8_t* ct_out,
    size_t ct_len,
    uint8_t* ss_out,
    size_t ss_len)
{
    (void)pk;
    (void)pk_len;
    (void)coins;
    (void)coins_len;
    (void)ct_out;
    (void)ct_len;
    (void)ss_out;
    (void)ss_len;
    return -1;
}

int tidecoin_node_mlkem512_decaps(
    const uint8_t* ct,
    size_t ct_len,
    const uint8_t* sk,
    size_t sk_len,
    uint8_t* ss_out,
    size_t ss_len)
{
    (void)ct;
    (void)ct_len;
    (void)sk;
    (void)sk_len;
    (void)ss_out;
    (void)ss_len;
    return -1;
}

int tidecoin_node_verify_tx_input(
    const char* tx_hex,
    size_t input_index,
    const uint8_t* prev_script,
    size_t prev_script_len,
    int64_t amount,
    uint32_t flags,
    int* script_error_out)
{
    (void)tx_hex;
    (void)input_index;
    (void)prev_script;
    (void)prev_script_len;
    (void)amount;
    (void)flags;
    if (script_error_out != NULL) {
        *script_error_out = 1;
    }
    return -1;
}

int tidecoin_node_parse_script_asm(
    const char* script_asm,
    uint8_t* out,
    size_t* out_len)
{
    (void)script_asm;
    (void)out;
    if (out_len != NULL) {
        *out_len = 0;
    }
    return -1;
}

int tidecoin_node_verify_script_case(
    const uint8_t* script_sig,
    size_t script_sig_len,
    const uint8_t* script_pubkey,
    size_t script_pubkey_len,
    const uint8_t* const* witness_items,
    const size_t* witness_lens,
    size_t witness_count,
    int64_t amount,
    uint32_t flags,
    int* script_error_out)
{
    (void)script_sig;
    (void)script_sig_len;
    (void)script_pubkey;
    (void)script_pubkey_len;
    (void)witness_items;
    (void)witness_lens;
    (void)witness_count;
    (void)amount;
    (void)flags;
    if (script_error_out != NULL) {
        *script_error_out = 1;
    }
    return -1;
}
