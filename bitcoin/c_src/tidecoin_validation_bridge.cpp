// SPDX-License-Identifier: CC0-1.0

#include <consensus/tx_check.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <logging.h>
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
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

bool VerifyInputInternal(const CTransaction& tx,
                         size_t input_index,
                         const CScript& prev_script,
                         int64_t amount,
                         uint32_t flags,
                         ScriptError* script_error)
{
    if (input_index >= tx.vin.size()) {
        if (script_error) *script_error = SCRIPT_ERR_UNKNOWN_ERROR;
        return false;
    }

    const bool allow_legacy = !(flags & SCRIPT_VERIFY_PQ_STRICT);
    const PrecomputedTransactionData txdata(tx);
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

TIDECOIN_BRIDGE_EXPORT int tidecoin_node_verify_tx_input(const char* tx_hex,
                                                         size_t input_index,
                                                         const uint8_t* prev_script,
                                                         size_t prev_script_len,
                                                         int64_t amount,
                                                         uint32_t flags,
                                                         int* script_error_out)
{
    try {
        CMutableTransaction decoded;
        if (!DecodeTxHex(decoded, tx_hex)) return -1;
        const CTransaction tx(decoded);
        const CScript prev(prev_script, prev_script + prev_script_len);
        ScriptError script_error{SCRIPT_ERR_OK};
        const bool ok = VerifyInputInternal(tx, input_index, prev, amount, flags, &script_error);
        if (script_error_out) *script_error_out = static_cast<int>(script_error);
        return ok ? 1 : 0;
    } catch (const std::exception&) {
        if (script_error_out) *script_error_out = static_cast<int>(SCRIPT_ERR_UNKNOWN_ERROR);
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
