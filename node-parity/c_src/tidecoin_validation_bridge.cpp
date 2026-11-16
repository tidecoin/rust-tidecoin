// SPDX-License-Identifier: CC0-1.0

#include <arith_uint256.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <crypto/scrypt.h>
#include <crypto/yespower/tidecoin_pow.h>
#include <hash.h>
#include <logging.h>
#include <pq/pq_api.h>
#include <pq/pq_txsize.h>
#include <primitives/block.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <streams.h>
#include <tinyformat.h>
#include <util/result.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include "spent_output.h"

using util::SplitString;

#if defined(__GNUC__) || defined(__clang__)
#define TIDECOIN_BRIDGE_EXPORT __attribute__((visibility("default")))
#else
#define TIDECOIN_BRIDGE_EXPORT
#endif

namespace {

class OpCodeParser
{
private:
    std::map<std::string, opcodetype> m_names;

public:
    OpCodeParser()
    {
        for (unsigned int op = 0; op <= MAX_OPCODE; ++op) {
            if (op < OP_NOP && op != OP_RESERVED) continue;
            const std::string name = GetOpName(static_cast<opcodetype>(op));
            if (name == "OP_UNKNOWN") continue;
            m_names[name] = static_cast<opcodetype>(op);
            if (name.starts_with("OP_")) {
                m_names[name.substr(3)] = static_cast<opcodetype>(op);
            }
        }
    }

    opcodetype Parse(const std::string& name) const
    {
        const auto it = m_names.find(name);
        if (it == m_names.end()) {
            throw std::runtime_error("script parse error: unknown opcode");
        }
        return it->second;
    }
};

opcodetype ParseOpCode(const std::string& s)
{
    static const OpCodeParser parser;
    return parser.Parse(s);
}

CScript ParseScriptAsm(const std::string& s)
{
    CScript result;
    for (const std::string& w : SplitString(s, " \t\n")) {
        if (w.empty()) {
            continue;
        } else if (std::all_of(w.begin(), w.end(), ::IsDigit) ||
                   (w.front() == '-' && w.size() > 1 &&
                    std::all_of(w.begin() + 1, w.end(), ::IsDigit))) {
            const auto num{ToIntegral<int64_t>(w)};
            if (!num.has_value() || num > int64_t{0xffffffff} || num < -int64_t{0xffffffff}) {
                throw std::runtime_error(
                    "script parse error: decimal numeric value only allowed in the range "
                    "-0xFFFFFFFF...0xFFFFFFFF");
            }
            result << num.value();
        } else if (w.starts_with("0x") && w.size() > 2 &&
                   IsHex(std::string(w.begin() + 2, w.end()))) {
            const std::vector<unsigned char> raw = ParseHex(std::string(w.begin() + 2, w.end()));
            result.insert(result.end(), raw.begin(), raw.end());
        } else if (w.size() >= 2 && w.front() == '\'' && w.back() == '\'') {
            std::vector<unsigned char> value(w.begin() + 1, w.end() - 1);
            result << value;
        } else {
            result << ParseOpCode(w);
        }
    }
    return result;
}

bool CheckTxScriptsSanity(const CMutableTransaction& tx)
{
    if (!CTransaction(tx).IsCoinBase()) {
        for (const auto& input : tx.vin) {
            if (!input.scriptSig.HasValidOps() || input.scriptSig.size() > MAX_SCRIPT_SIZE) {
                return false;
            }
        }
    }
    for (const auto& output : tx.vout) {
        if (!output.scriptPubKey.HasValidOps() || output.scriptPubKey.size() > MAX_SCRIPT_SIZE) {
            return false;
        }
    }
    return true;
}

bool DecodeTxHex(CMutableTransaction& tx, const char* hex_tx)
{
    if (hex_tx == nullptr) return false;
    const std::string hex{hex_tx};
    if (!IsHex(hex)) return false;
    const std::vector<unsigned char> tx_data = ParseHex(hex);

    CMutableTransaction tx_extended, tx_legacy;
    bool ok_extended = false;
    bool ok_legacy = false;

    {
        DataStream ss(tx_data);
        try {
            ss >> TX_WITH_WITNESS(tx_extended);
            if (ss.empty()) ok_extended = true;
        } catch (const std::exception&) {
        }
    }
    if (ok_extended && CheckTxScriptsSanity(tx_extended)) {
        tx = std::move(tx_extended);
        return true;
    }

    {
        DataStream ss(tx_data);
        try {
            ss >> TX_NO_WITNESS(tx_legacy);
            if (ss.empty()) ok_legacy = true;
        } catch (const std::exception&) {
        }
    }
    if (ok_legacy && CheckTxScriptsSanity(tx_legacy)) {
        tx = std::move(tx_legacy);
        return true;
    }
    if (ok_extended) {
        tx = std::move(tx_extended);
        return true;
    }
    if (ok_legacy) {
        tx = std::move(tx_legacy);
        return true;
    }
    return false;
}

bool DecodeHeaderHex(CBlockHeader& header, const char* hex_header)
{
    if (hex_header == nullptr) return false;
    const std::string hex{hex_header};
    if (!IsHex(hex)) return false;
    const std::vector<unsigned char> header_data = ParseHex(hex);

    DataStream ss(header_data);
    try {
        ss >> header;
        return ss.empty();
    } catch (const std::exception&) {
        return false;
    }
}

bool DecodeBlockHex(CBlock& block, const char* hex_block)
{
    if (hex_block == nullptr) return false;
    const std::string hex{hex_block};
    if (!IsHex(hex)) return false;
    const std::vector<unsigned char> block_data = ParseHex(hex);

    DataStream ss(block_data);
    try {
        ss >> TX_WITH_WITNESS(block);
        return ss.empty();
    } catch (const std::exception&) {
        return false;
    }
}

Consensus::Params BridgeConsensusParams(int network)
{
    Consensus::Params params{};
    params.nAuxpowChainId = 8;
    params.fStrictChainId = true;
    params.nPowTargetSpacing = 60;
    params.nPowAveragingWindow = 17;

    switch (network) {
    case 0:
        params.nSubsidyHalvingInterval = 262800;
        params.nAuxpowStartHeight = Consensus::AUXPOW_DISABLED;
        params.powLimit =
            uint256{"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        params.fPowAllowMinDifficultyBlocks = false;
        params.fPowNoRetargeting = false;
        params.nPowTargetTimespan = 432000;
        params.nPowMaxAdjustDown = 32;
        params.nPowMaxAdjustUp = 16;
        break;
    case 1:
        params.nSubsidyHalvingInterval = 262800;
        params.nAuxpowStartHeight = 1000;
        params.powLimit =
            uint256{"01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        params.fPowAllowMinDifficultyBlocks = true;
        params.fPowNoRetargeting = false;
        params.nPowTargetTimespan = 432000;
        params.nPowMaxAdjustDown = 32;
        params.nPowMaxAdjustUp = 16;
        break;
    case 2:
        params.nSubsidyHalvingInterval = 20;
        params.nAuxpowStartHeight = 0;
        params.fPowGenesisScrypt = true;
        params.powLimit =
            uint256{"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"};
        params.fPowAllowMinDifficultyBlocks = true;
        params.fPowNoRetargeting = true;
        params.nPowTargetTimespan = 14400;
        params.nPowMaxAdjustDown = 0;
        params.nPowMaxAdjustUp = 0;
        break;
    default:
        throw std::runtime_error("unknown Tidecoin network id");
    }

    return params;
}

CScriptWitness BuildWitness(const uint8_t* const* items, const size_t* lens, size_t count)
{
    CScriptWitness witness;
    if (items == nullptr || lens == nullptr) return witness;
    witness.stack.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto* ptr = items[i];
        const size_t len = lens[i];
        witness.stack.emplace_back(ptr, ptr + len);
    }
    return witness;
}

bool ReadSpentOutputs(const TidecoinSpentOutput* supplied, size_t count, size_t inputs,
                      std::vector<CTxOut>& outputs)
{
    // Node Init asserts on partial context. A malformed bridge request is not
    // a consensus verdict; preserve empty context for missing-data/ACP tests.
    if (count != 0 && (count != inputs || supplied == nullptr)) return false;
    outputs.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const auto& out = supplied[i];
        if (out.script == nullptr) return false;
        outputs.emplace_back(out.amount, CScript(out.script, out.script + out.script_len));
    }
    return true;
}

bool VerifyInputInternal(const CTransaction& tx,
                         size_t input_index,
                         const CScript& prev_script,
                         int64_t amount,
                         uint32_t flags,
                         ScriptError* script_error,
                         std::vector<CTxOut> spent_outputs = {})
{
    if (input_index >= tx.vin.size()) {
        if (script_error) *script_error = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(spent_outputs));
    return VerifyScript(tx.vin[input_index].scriptSig,
                        prev_script,
                        &tx.vin[input_index].scriptWitness,
                        flags,
                        TransactionSignatureChecker(
                            &tx,
                            static_cast<unsigned int>(input_index),
                            amount,
                            txdata,
                            MissingDataBehavior::FAIL,
                            allow_legacy),
                        script_error);
}

} // namespace

namespace BCLog {

const char* const DEFAULT_DEBUGLOGFILE = "debug.log";
bool fLogIPs = false;

Logger& LogInstance()
{
    static Logger logger;
    logger.DisableLogging();
    return logger;
}

void Logger::LogPrintStr(
    std::string_view,
    std::source_location&&,
    BCLog::LogFlags,
    BCLog::Level,
    bool)
{
}

void Logger::DisableLogging()
{
    m_print_to_file = false;
    m_print_to_console = false;
}

bool Logger::WillLogCategoryLevel(LogFlags, Level) const
{
    return false;
}

} // namespace BCLog

BCLog::Logger& LogInstance()
{
    return BCLog::LogInstance();
}

extern "C" {

// Strict wire decoding, without DecodeTxHex's RPC legacy/witness heuristics.
// 0: malformed wire input, 1: decoded but CheckTransaction rejects, 2: valid.
TIDECOIN_BRIDGE_EXPORT int tidecoin_node_transaction_status(const uint8_t* bytes, size_t len)
{
    if (bytes == nullptr && len != 0) return -1;
    try {
        DataStream stream{std::span<const uint8_t>{bytes, len}};
        CMutableTransaction tx;
        stream >> TX_WITH_WITNESS(tx);
        if (!stream.empty()) return 0;
        TxValidationState state;
        return CheckTransaction(CTransaction(tx), state) ? 2 : 1;
    } catch (const std::ios_base::failure&) {
        return 0;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_check_transaction(const char* tx_hex)
{
    try {
        CMutableTransaction tx;
        if (!DecodeTxHex(tx, tx_hex)) return 0;
        TxValidationState state;
        return CheckTransaction(CTransaction(tx), state) ? 1 : 0;
    } catch (const std::exception&) {
        return 0;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_scrypt_pow_hash(
    const uint8_t* header,
    size_t header_len,
    uint8_t* out,
    size_t out_len)
{
    if (header == nullptr || out == nullptr || header_len != 80 || out_len != 32) return -1;
    try {
        scrypt_1024_1_1_256(reinterpret_cast<const char*>(header), reinterpret_cast<char*>(out));
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_yespower_pow_hash(
    const uint8_t* header,
    size_t header_len,
    uint8_t* out,
    size_t out_len)
{
    if (header == nullptr || out == nullptr || header_len != 80 || out_len != 32) return -1;
    try {
        uint256 pow_hash;
        if (!TidecoinYespowerHash(std::span<const unsigned char>(header, header_len), pow_hash)) {
            return 0;
        }
        std::copy(pow_hash.begin(), pow_hash.end(), out);
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}



TIDECOIN_BRIDGE_EXPORT int tidecoin_node_uses_scrypt_pow(int network, int height, int activation_height)
{
    try {
        auto params = BridgeConsensusParams(network);
        params.nAuxpowStartHeight = activation_height;
        return UseScryptPoW(params, height) ? 1 : 0;
    } catch (const std::exception&) {
        return -1;
    }
}





TIDECOIN_BRIDGE_EXPORT int tidecoin_node_permitted_difficulty_transition(
    int network,
    int64_t height,
    uint32_t old_nbits,
    uint32_t new_nbits)
{
    try {
        const Consensus::Params params = BridgeConsensusParams(network);
        return PermittedDifficultyTransition(params, height, old_nbits, new_nbits) ? 1 : 0;
    } catch (const std::exception&) {
        return -1;
    }
}



TIDECOIN_BRIDGE_EXPORT int64_t tidecoin_node_pq_p2wpkh_input_vsize(size_t sig_len, size_t pubkey_len)
{
    return pq::VSizeP2WPKHInput(sig_len, pubkey_len);
}

TIDECOIN_BRIDGE_EXPORT int64_t tidecoin_node_pq_p2sh_p2wpkh_input_vsize(size_t sig_len, size_t pubkey_len)
{
    return pq::VSizeP2SH_P2WPKHInput(sig_len, pubkey_len);
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_pq_keygen_from_seed(
    uint8_t scheme_prefix,
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* pk_out,
    size_t pk_len,
    uint8_t* sk_out,
    size_t sk_len)
{
    try {
        const pq::SchemeInfo* info = pq::SchemeFromPrefix(scheme_prefix);
        if (info == nullptr || seed == nullptr || pk_out == nullptr || sk_out == nullptr) return -1;
        if (pk_len != info->pubkey_bytes || sk_len != info->seckey_bytes) return 0;

        int rc = -1;
        switch (info->id) {
        case pq::SchemeId::FALCON_512:
            rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair_deterministic(pk_out, sk_out, seed, seed_len);
            break;
        case pq::SchemeId::FALCON_1024:
            rc = PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair_deterministic(pk_out, sk_out, seed, seed_len);
            break;
        case pq::SchemeId::MLDSA_44:
            rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_deterministic(pk_out, sk_out, seed, seed_len);
            break;
        case pq::SchemeId::MLDSA_65:
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_deterministic(pk_out, sk_out, seed, seed_len);
            break;
        case pq::SchemeId::MLDSA_87:
            rc = PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair_deterministic(pk_out, sk_out, seed, seed_len);
            break;
        default:
            return 0;
        }

        return rc == 0 ? 1 : 0;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_pqhd_keygen_from_stream_key(
    uint8_t scheme_prefix,
    const uint8_t* stream_key,
    size_t stream_key_len,
    uint8_t* pk_out,
    size_t pk_len,
    uint8_t* sk_out,
    size_t sk_len)
{
    try {
        const pq::SchemeInfo* info = pq::SchemeFromPrefix(scheme_prefix);
        if (info == nullptr || stream_key == nullptr || pk_out == nullptr || sk_out == nullptr) return -1;
        if (pk_len != info->pubkey_bytes || sk_len != info->seckey_bytes) return 0;

        std::vector<uint8_t> pk;
        pq::SecureKeyBytes sk;
        const bool ok = pq::KeyGenFromSeedBytes(
            /*pqhd_version=*/1,
            info->id,
            std::span<const uint8_t>(stream_key, stream_key_len),
            pk,
            sk);
        if (!ok || pk.size() != pk_len || sk.size() != sk_len) return 0;

        std::copy(pk.begin(), pk.end(), pk_out);
        std::copy(sk.begin(), sk.end(), sk_out);
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_pq_compute_public_key(
    uint8_t scheme_prefix,
    const uint8_t* sk,
    size_t sk_len,
    uint8_t* pk_out,
    size_t pk_len)
{
    try {
        const pq::SchemeInfo* info = pq::SchemeFromPrefix(scheme_prefix);
        if (info == nullptr || sk == nullptr || pk_out == nullptr) return -1;
        const bool ok = pq::ComputePublicKeyFromSecret(
            *info,
            std::span<const unsigned char>(sk, sk_len),
            std::span<unsigned char>(pk_out, pk_len));
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_pq_sign_message(
    uint8_t scheme_prefix,
    const uint8_t* msg,
    size_t msg_len,
    const uint8_t* sk,
    size_t sk_len,
    int legacy_mode,
    uint8_t* sig_out,
    size_t* sig_len)
{
    if (msg == nullptr || sk == nullptr || sig_len == nullptr) return -1;
    try {
        const pq::SchemeInfo* info = pq::SchemeFromPrefix(scheme_prefix);
        if (info == nullptr) return -1;

        std::vector<unsigned char> sig;
        const bool ok = msg_len == 32
            ? pq::Sign(*info, std::span<const unsigned char>(msg, msg_len), std::span<const unsigned char>(sk, sk_len), sig, legacy_mode != 0)
            : msg_len == 64
                ? pq::Sign64(*info, std::span<const unsigned char>(msg, msg_len), std::span<const unsigned char>(sk, sk_len), sig, legacy_mode != 0)
                : false;
        if (!ok) return 0;

        if (sig_out == nullptr || *sig_len < sig.size()) {
            *sig_len = sig.size();
            return 0;
        }
        std::copy(sig.begin(), sig.end(), sig_out);
        *sig_len = sig.size();
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_pq_verify_message(
    uint8_t scheme_prefix,
    const uint8_t* msg,
    size_t msg_len,
    const uint8_t* sig,
    size_t sig_len,
    const uint8_t* pk,
    size_t pk_len,
    int legacy_mode)
{
    if (msg == nullptr || sig == nullptr || pk == nullptr) return -1;
    try {
        const pq::SchemeInfo* info = pq::SchemeFromPrefix(scheme_prefix);
        if (info == nullptr) return -1;

        const bool ok = msg_len == 32
            ? pq::Verify(
                *info,
                std::span<const unsigned char>(msg, msg_len),
                std::span<const unsigned char>(sig, sig_len),
                std::span<const unsigned char>(pk, pk_len),
                legacy_mode != 0)
            : msg_len == 64
                ? pq::Verify64(
                    *info,
                    std::span<const unsigned char>(msg, msg_len),
                    std::span<const unsigned char>(sig, sig_len),
                    std::span<const unsigned char>(pk, pk_len),
                    legacy_mode != 0)
                : false;
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_verify_tx_input(const char* tx_hex,
                                                         size_t input_index,
                                                         const uint8_t* prev_script,
                                                         size_t prev_script_len,
                                                         int64_t amount,
                                                         uint32_t flags,
                                                         const TidecoinSpentOutput* spent_outputs,
                                                         size_t spent_output_count,
                                                         int* script_error_out)
{
    try {
        CMutableTransaction decoded;
        if (!DecodeTxHex(decoded, tx_hex)) return -1;
        const CTransaction tx(decoded);
        std::vector<CTxOut> outputs;
        if (!ReadSpentOutputs(spent_outputs, spent_output_count, tx.vin.size(), outputs)) return -1;
        const CScript prev(prev_script, prev_script + prev_script_len);
        ScriptError script_error{SCRIPT_ERR_OK};
        const bool ok = VerifyInputInternal(tx, input_index, prev, amount, flags, &script_error, std::move(outputs));
        if (script_error_out) *script_error_out = static_cast<int>(script_error);
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        if (script_error_out) *script_error_out = static_cast<int>(SCRIPT_ERR_UNKNOWN_ERROR);
        return -1;
    }
}

// Calls the original node helper; no copied sigop-counting rules.
TIDECOIN_BRIDGE_EXPORT int64_t tidecoin_node_count_witness_sigops(
    const char* tx_hex, size_t input_index, const unsigned char* prev_script,
    size_t prev_script_len, unsigned int flags)
{
    try {
        CMutableTransaction tx;
        if (!DecodeTxHex(tx, tx_hex) || input_index >= tx.vin.size()) return -1;
        // The original helper asserts this flag dependency.
        if ((flags & SCRIPT_VERIFY_WITNESS) && !(flags & SCRIPT_VERIFY_P2SH)) return -1;
        CScript script(prev_script, prev_script + prev_script_len);
        return CountWitnessSigOps(tx.vin[input_index].scriptSig, script, &tx.vin[input_index].scriptWitness, flags);
    } catch (...) { return -1; }
}

// Calls the node implementation directly; no Rust or bridge copy of the preimage.
TIDECOIN_BRIDGE_EXPORT int tidecoin_node_signature_hash_512(
    const char* tx_hex, size_t input_index, const uint8_t* script, size_t script_len,
    int64_t amount, int32_t hash_type, const TidecoinSpentOutput* spent_outputs,
    size_t spent_output_count, uint8_t* hash_out)
{
    try {
        CMutableTransaction decoded;
        if (!DecodeTxHex(decoded, tx_hex) || input_index >= decoded.vin.size()) return -1;
        std::vector<CTxOut> outputs;
        if (!ReadSpentOutputs(spent_outputs, spent_output_count, decoded.vin.size(), outputs)) return -1;
        PrecomputedTransactionData data;
        // Signing callers (sign.cpp/psbt.cpp) force precomputation before witnesses exist.
        data.Init(decoded, std::move(outputs), true);
        uint512 hash;
        if (!SignatureHash512(hash, CScript(script, script + script_len), decoded,
                              input_index, hash_type, amount, &data)) return 0;
        std::copy(hash.begin(), hash.end(), hash_out);
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_mlkem512_keypair_from_coins(
    const uint8_t* coins,
    size_t coins_len,
    uint8_t* pk_out,
    size_t pk_len,
    uint8_t* sk_out,
    size_t sk_len)
{
    try {
        if (coins == nullptr || pk_out == nullptr || sk_out == nullptr) return -1;
        if (pk_len != pq::MLKEM512_PUBLICKEY_BYTES ||
            sk_len != pq::MLKEM512_SECRETKEY_BYTES ||
            coins_len != pq::MLKEM512_KEYPAIR_COINS_BYTES) {
            return 0;
        }

        pq::MLKEM512Keypair keypair;
        if (!keypair.GenerateDeterministic(std::span<const uint8_t>(coins, coins_len))) return 0;
        const auto pk = keypair.PublicKey();
        const auto sk = keypair.SecretKey();
        std::copy(pk.begin(), pk.end(), pk_out);
        std::copy(sk.begin(), sk.end(), sk_out);
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_mlkem512_encaps_deterministic(
    const uint8_t* pk,
    size_t pk_len,
    const uint8_t* coins,
    size_t coins_len,
    uint8_t* ct_out,
    size_t ct_len,
    uint8_t* ss_out,
    size_t ss_len)
{
    try {
        if (pk == nullptr || coins == nullptr || ct_out == nullptr || ss_out == nullptr) return -1;
        const bool ok = pq::MLKEM512EncapsDeterministic(
            std::span<const uint8_t>(pk, pk_len),
            std::span<const uint8_t>(coins, coins_len),
            std::span<uint8_t>(ct_out, ct_len),
            std::span<uint8_t>(ss_out, ss_len));
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_mlkem512_decaps(
    const uint8_t* ct,
    size_t ct_len,
    const uint8_t* sk,
    size_t sk_len,
    uint8_t* ss_out,
    size_t ss_len)
{
    try {
        if (ct == nullptr || sk == nullptr || ss_out == nullptr) return -1;
        const bool ok = pq::MLKEM512Decaps(
            std::span<const uint8_t>(ct, ct_len),
            std::span<const uint8_t>(sk, sk_len),
            std::span<uint8_t>(ss_out, ss_len));
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_parse_script_asm(
    const char* script_asm,
    uint8_t* out,
    size_t* out_len)
{
    if (out_len == nullptr || script_asm == nullptr) return -1;
    try {
        const CScript script = ParseScriptAsm(script_asm);
        if (out == nullptr || *out_len < script.size()) {
            *out_len = script.size();
            return 0;
        }
        std::copy(script.begin(), script.end(), out);
        *out_len = script.size();
        return 1;
    } catch (const std::exception&) {
        return -1;
    }
}

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_verify_script_case(
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
    try {
        const CScript script_sig_cs(script_sig, script_sig + script_sig_len);
        const CScript script_pubkey_cs(script_pubkey, script_pubkey + script_pubkey_len);
        const CScriptWitness witness = BuildWitness(witness_items, witness_lens, witness_count);

        CMutableTransaction tx_credit;
        tx_credit.version = 1;
        tx_credit.nLockTime = 0;
        tx_credit.vin.resize(1);
        tx_credit.vout.resize(1);
        tx_credit.vin[0].prevout.SetNull();
        tx_credit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
        tx_credit.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        tx_credit.vout[0].scriptPubKey = script_pubkey_cs;
        tx_credit.vout[0].nValue = amount;

        const CTransaction credit(tx_credit);
        CMutableTransaction tx_spend;
        tx_spend.version = 1;
        tx_spend.nLockTime = 0;
        tx_spend.vin.resize(1);
        tx_spend.vout.resize(1);
        tx_spend.vin[0].scriptWitness = witness;
        tx_spend.vin[0].prevout.hash = credit.GetHash();
        tx_spend.vin[0].prevout.n = 0;
        tx_spend.vin[0].scriptSig = script_sig_cs;
        tx_spend.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        tx_spend.vout[0].scriptPubKey = CScript();
        tx_spend.vout[0].nValue = amount;

        const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
        // Match src/test/script_tests.cpp::DoTest, including the actual credit output.
        PrecomputedTransactionData txdata;
        txdata.Init(tx_spend, {credit.vout[0]}, true);
        ScriptError script_error{SCRIPT_ERR_OK};
        const bool ok = VerifyScript(
            tx_spend.vin[0].scriptSig,
            script_pubkey_cs,
            &tx_spend.vin[0].scriptWitness,
            flags,
            MutableTransactionSignatureChecker(
                &tx_spend,
                0,
                credit.vout[0].nValue,
                txdata,
                MissingDataBehavior::ASSERT_FAIL,
                allow_legacy),
            &script_error);
        if (script_error_out) *script_error_out = static_cast<int>(script_error);
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        if (script_error_out) *script_error_out = static_cast<int>(SCRIPT_ERR_UNKNOWN_ERROR);
        return -1;
    }
}

} // extern "C"
