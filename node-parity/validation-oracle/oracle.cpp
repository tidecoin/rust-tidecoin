// SPDX-License-Identifier: CC0-1.0
// Include the complete, unmodified translation unit to access its static checks.
// No rule bodies are copied or extracted into this harness.
#include <validation.cpp>
#include <kernel/notifications_interface.h>
#include <univalue.h>
#include <key_io.h>
#include <pq/pqhd_kdf.h>
#include <pq/pq_api.h>
#include <policy/policy.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <net_processing.h>
#include <util/signalinterrupt.h>
#include <iostream>
#include <iterator>

// Standalone programs supply the node's optional UI translation hook.
const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

class OracleParams : public CChainParams {
public:
    explicit OracleParams(const CChainParams& base) : CChainParams(base) {}
    Consensus::Params& MutableConsensus() { return consensus; }
};

static int Int(const UniValue& v, const char* key, int fallback)
{
    return v.exists(key) ? v[key].getInt<int>() : fallback;
}
static bool Bool(const UniValue& v, const char* key, bool fallback)
{
    return v.exists(key) ? v[key].get_bool() : fallback;
}
static OracleParams ParamsFor(const UniValue& request)
{
    std::unique_ptr<const CChainParams> base;
    switch (Int(request, "network", 2)) {
    case 0: base = CChainParams::Main(); break;
    case 1: base = CChainParams::TestNet(); break;
    case 2: base = CChainParams::RegTest({}); break;
    default: throw std::runtime_error("unknown network");
    }
    OracleParams params{*base};
    auto& p = params.MutableConsensus();
    const auto& overrides = request["params"];
    p.nAuxpowStartHeight = Int(overrides, "auxpow_start_height", p.nAuxpowStartHeight);
    p.BIP34Height = Int(overrides, "bip34_height", p.BIP34Height);
    p.BIP65Height = Int(overrides, "bip65_height", p.BIP65Height);
    p.BIP66Height = Int(overrides, "bip66_height", p.BIP66Height);
    p.CSVHeight = Int(overrides, "csv_height", p.CSVHeight);
    p.SegwitHeight = Int(overrides, "segwit_height", p.SegwitHeight);
    p.enforce_BIP94 = Bool(overrides, "enforce_bip94", p.enforce_BIP94);
    p.fStrictChainId = Bool(overrides, "strict_chain_id", p.fStrictChainId);
    p.fPowNoRetargeting = Bool(overrides, "no_retargeting", p.fPowNoRetargeting);
    p.nPowTargetTimespan = Int(overrides, "target_timespan", p.nPowTargetTimespan);
    return params;
}
class DecodeError : public std::runtime_error { using std::runtime_error::runtime_error; };

static CBlockHeader Header(const UniValue& hex, bool pure = false)
{
    if (!IsHex(hex.get_str())) throw DecodeError("invalid header hex");
    DataStream stream{ParseHex(hex.get_str())};
    CBlockHeader header;
    try {
    if (pure) stream >> header.nVersion >> header.hashPrevBlock >> header.hashMerkleRoot >> header.nTime >> header.nBits >> header.nNonce;
    else stream >> header;
    } catch (const std::ios_base::failure& e) { throw DecodeError(e.what()); }
    if (!stream.empty()) throw DecodeError("trailing header bytes");
    return header;
}
static CBlock Block(const UniValue& hex)
{
    if (!IsHex(hex.get_str())) throw DecodeError("invalid block hex");
    DataStream stream{ParseHex(hex.get_str())};
    CBlock block;
    try { stream >> TX_WITH_WITNESS(block); }
    catch (const std::ios_base::failure& e) { throw DecodeError(e.what()); }
    if (!stream.empty()) throw DecodeError("trailing block bytes");
    return block;
}
static UniValue Verdict(bool valid, const BlockValidationState& state)
{
    UniValue result{UniValue::VOBJ};
    result.pushKV("valid", valid);
    result.pushKV("reason", state.GetRejectReason());
    result.pushKV("result", static_cast<int>(state.GetResult()));
    result.pushKV("mutated", state.GetResult() == BlockValidationResult::BLOCK_MUTATED);
    return result;
}

// A real ChainstateManager owns deployment decisions and caches. The history is
// caller-supplied, as in Rust's header API; no UTXO acceptance is claimed.
static UniValue Run(const UniValue& request, const fs::path& datadir)
{
    auto params = ParamsFor(request);
    const std::string op = request["op"].get_str();
    const auto& p = params.GetConsensus();
    BlockValidationState state;
    if (op == "signed_tx_cost" || op == "tx_weight") {
        DataStream stream{ParseHex(request["tx"].get_str())};
        CMutableTransaction decoded;
        stream >> TX_WITH_WITNESS(decoded);
        if (!stream.empty()) throw DecodeError("trailing transaction bytes");
        const CTransaction tx{decoded};
        const auto vsize = GetVirtualTransactionSize(tx);
        UniValue out{UniValue::VOBJ};
        out.pushKV("weight", GetTransactionWeight(tx));
        out.pushKV("vsize", vsize);
        out.pushKV("rate_fee", CFeeRate{request["rate"].getInt<CAmount>()}.GetFee(vsize));
        if (op == "tx_weight") {
            // Serialization-only sizing, including synthetic maximum satisfactions.
            // No wallet funding, script acceptance or UTXO validity is implied.
            UniValue weights{UniValue::VARR};
            for (const auto& input : tx.vin) weights.push_back(GetTransactionInputWeight(input));
            out.pushKV("input_weights", weights);
            return out;
        }
        const auto& spent = request["spent"].getValues();
        if (spent.size() != tx.vin.size()) throw DecodeError("spent output count");
        CCoinsView base;
        CCoinsViewCache coins{&base};
        for (size_t i = 0; i < spent.size(); ++i) {
            const auto script = ParseHex(spent[i]["script"].get_str());
            coins.AddCoin(tx.vin[i].prevout, Coin{CTxOut{spent[i]["amount"].getInt<CAmount>(),
                CScript{script.begin(), script.end()}}, 1, false}, false);
        }
        TxValidationState tx_state;
        CAmount paid_fee{0};
        if (!Consensus::CheckTxInputs(tx, tx_state, coins, 2, paid_fee))
            throw std::runtime_error(tx_state.ToString());
        out.pushKV("paid_fee", paid_fee);
        return out;
    }
    if (op == "pq_estimate") {
        const auto bytes = ParseHex(request["pubkey"].get_str());
        const CPubKey pubkey{bytes};
        FlatSigningProvider provider;
        if (pubkey.IsValid() && !Bool(request, "unknown", false)) provider.pubkeys.emplace(pubkey.GetID(), pubkey);
        const auto& creator = Bool(request, "maximum", false)
            ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR;
        std::vector<unsigned char> sig;
        if (!creator.CreateSig(provider, sig, pubkey.GetID(), CScript{}, SigVersion::BASE))
            throw std::runtime_error("dummy signing failed");
        CTxIn input;
        const auto kind = request["kind"].get_str();
        if (kind == "pkh") {
            input.scriptSig = CScript{} << sig << bytes;
        } else if (kind == "wpkh" || kind == "sh-wpkh") {
            input.scriptWitness.stack = {sig, bytes};
            if (kind == "sh-wpkh") {
                const CScript redeem = CScript{} << OP_0 << std::vector<unsigned char>(20);
                input.scriptSig = CScript{} << std::vector<unsigned char>(redeem.begin(), redeem.end());
            }
        } else if (kind == "wsh" || kind == "wsh512") {
            const CScript witness = CScript{} << bytes << OP_CHECKSIG;
            input.scriptWitness.stack = {sig, {witness.begin(), witness.end()}};
        } else throw std::runtime_error("unknown estimate kind");
        CMutableTransaction tx;
        tx.vin.assign(Int(request, "inputs", 1), input);
        tx.vout.assign(Int(request, "outputs", 1), CTxOut{1, CScript{}});
        for (auto& output : tx.vout) output.scriptPubKey.resize(Int(request, "output_len", 1));
        const CTransaction transaction{tx};
        const auto weight = GetTransactionWeight(transaction);
        const auto vsize = GetVirtualTransactionSize(transaction);
        UniValue out{UniValue::VOBJ};
        out.pushKV("sig_len", sig.size());
        out.pushKV("weight", weight);
        out.pushKV("vsize", vsize);
        out.pushKV("fee", CFeeRate{Int(request, "rate", 1000)}.GetFee(vsize));
        return out;
    }
    if (op == "fee" || op == "dust" || op == "script_push") {
        UniValue out{UniValue::VOBJ};
        if (op == "fee") {
            out.pushKV("fee", CFeeRate{Int(request, "rate", 0)}.GetFee(Int(request, "vsize", 0)));
        } else if (op == "dust") {
            const auto bytes = ParseHex(request["script"].get_str());
            out.pushKV("dust", GetDustThreshold(CTxOut{0, CScript(bytes.begin(), bytes.end())}, CFeeRate{Int(request, "rate", 0)}));
        } else {
            const CScript script = CScript{} << std::vector<unsigned char>(Int(request, "size", 0), 0x42);
            out.pushKV("size", script.size());
        }
        return out;
    }
    if (op == "headers_size") {
        HeadersMessageSize size;
        for (const auto& value : request["sizes"].getValues()) size.Add(value.getInt<size_t>());
        UniValue out{UniValue::VOBJ};
        out.pushKV("size", size.GetSize());
        out.pushKV("full", size.IsFull(Int(request, "max_count", MAX_HEADERS_RESULTS)));
        out.pushKV("max_message", MAX_PROTOCOL_MESSAGE_LENGTH);
        out.pushKV("max_header", MAX_BLOCK_HEADER_SIZE);
        return out;
    }
    if (op == "falcon_encoding" || op == "pubkey_valid") {
        const auto bytes = ParseHex(request["bytes"].get_str());
        UniValue out{UniValue::VOBJ};
        out.pushKV("valid", op == "falcon_encoding" ? pq::IsNonCanonicalLegacyFalcon512(bytes) : pq::IsValidPubKey(bytes));
        return out;
    }
    if (op == "pqhd_path") {
        std::vector<uint32_t> path;
        for (const auto& value : request["path"].getValues()) path.push_back(value.getInt<uint32_t>());
        UniValue out{UniValue::VOBJ};
        out.pushKV("valid", pqhd::ValidateV1LeafPath(path));
        if (pqhd::ValidateV1LeafPath(path)) {
            std::array<uint8_t, 32> seed{};
            seed.fill(42);
            const auto master = pqhd::MakeMasterNode(seed);
            const auto leaf = pqhd::DerivePath(master, path);
            const auto material = pqhd::DeriveKeygenStreamKey(leaf->node_secret, path);
            out.pushKV("stream", HexStr(*material));
        }
        return out;
    }
    if (op == "wif") {
        SelectParams(Int(request, "network", 2) == 0 ? ChainType::MAIN : Int(request, "network", 2) == 1 ? ChainType::TESTNET : ChainType::REGTEST);
        const auto key = DecodeSecret(request["wif"].get_str());
        UniValue out{UniValue::VOBJ};
        out.pushKV("valid", key.IsValid());
        if (key.IsValid()) {
            out.pushKV("legacy", EncodeSecretLegacy(key));
            out.pushKV("prefixed", EncodeSecret(key));
        }
        return out;
    }
    if (op == "header_size") {
        auto header = Header(request["header"]);
        if (Bool(request, "drop_auxpow", false)) header.auxpow.reset();
        if (Bool(request, "clear_auxpow_flag", false)) header.SetAuxpowVersion(false);
        UniValue out{UniValue::VOBJ};
        out.pushKV("oversized", IsOversizedAuxPowHeader(header));
        if (!header.IsAuxpow() || header.auxpow) out.pushKV("size", GetSerializeSize(header));
        return out;
    }
    if (op == "witness_policy") {
        CMutableTransaction mutable_tx;
        DataStream stream{ParseHex(request["tx"].get_str())};
        stream >> TX_WITH_WITNESS(mutable_tx);
        if (!stream.empty()) throw DecodeError("trailing transaction bytes");
        const CTransaction tx{mutable_tx};
        CCoinsView base;
        CCoinsViewCache coins{&base};
        const auto bytes = ParseHex(request["prev_script"].get_str());
        const CScript script{bytes.begin(), bytes.end()};
        for (const auto& input : tx.vin) coins.AddCoin(input.prevout, Coin{CTxOut{1000, script}, 1, false}, false);
        UniValue out{UniValue::VOBJ};
        out.pushKV("standard", IsWitnessStandard(tx, coins));
        out.pushKV("dependent", SpendsNonAnchorWitnessProg(tx, coins, request["flags"].getInt<unsigned int>()));
        return out;
    }
    if (op == "params") {
        UniValue out{UniValue::VOBJ};
        out.pushKV("auxpow_start_height", p.nAuxpowStartHeight);
        out.pushKV("bip34_height", p.BIP34Height);
        out.pushKV("bip65_height", p.BIP65Height);
        out.pushKV("bip66_height", p.BIP66Height);
        out.pushKV("csv_height", p.CSVHeight);
        out.pushKV("segwit_height", p.SegwitHeight);
        out.pushKV("enforce_bip94", p.enforce_BIP94);
        out.pushKV("strict_chain_id", p.fStrictChainId);
        out.pushKV("no_retargeting", p.fPowNoRetargeting);
        out.pushKV("target_timespan", p.nPowTargetTimespan);
        out.pushKV("genesis_scrypt", p.fPowGenesisScrypt);
        out.pushKV("chain_id", p.nAuxpowChainId);
        out.pushKV("subsidy_interval", p.nSubsidyHalvingInterval);
        out.pushKV("pow_limit_compact", UintToArith256(p.powLimit).GetCompact());
        out.pushKV("target_spacing", p.nPowTargetSpacing);
        out.pushKV("allow_min_difficulty", p.fPowAllowMinDifficultyBlocks);
        if (p.nPowAllowMinDifficultyBlocksAfterHeight) out.pushKV("min_difficulty_after", *p.nPowAllowMinDifficultyBlocksAfterHeight);
        else out.pushKV("min_difficulty_after", UniValue{});
        out.pushKV("averaging_window", p.nPowAveragingWindow);
        out.pushKV("max_adjust_down", p.nPowMaxAdjustDown);
        out.pushKV("max_adjust_up", p.nPowMaxAdjustUp);
        return out;
    }
    if (op == "subsidy") {
        const int height = request["height"].getInt<int>();
        if (height < 0) throw std::runtime_error("negative subsidy height");
        UniValue out{UniValue::VOBJ};
        out.pushKV("subsidy", GetBlockSubsidy(height, p));
        return out;
    }
    if (op == "proof") {
        auto header = Header(request["header"], Bool(request, "pure_header", false));
        if (Bool(request, "drop_auxpow", false)) header.auxpow.reset();
        if (Bool(request, "clear_auxpow_flag", false)) header.SetAuxpowVersion(false);
        const auto height = request["height"].isNull() ? std::nullopt : std::make_optional(request["height"].getInt<int>());
        const bool valid = CheckBlockHeader(header, state, p, true, height);
        return Verdict(valid, state);
    }
    if (op == "block") {
        const auto block = Block(request["block"]);
        const bool valid = CheckBlock(block, state, p, Bool(request, "check_pow", false), Bool(request, "check_merkle", true));
        return Verdict(valid, state);
    }
    if (op == "witness") {
        const auto block = Block(request["block"]);
        if (!CheckBlock(block, state, p, false, true)) return Verdict(false, state);
        const bool valid = CheckWitnessMalleation(block, Bool(request, "expect_witness", true), state);
        return Verdict(valid, state);
    }
    if (op == "finality") {
        CMutableTransaction tx;
        DataStream stream{ParseHex(request["tx"].get_str())};
        stream >> TX_WITH_WITNESS(tx);
        if (!stream.empty()) throw std::runtime_error("trailing transaction bytes");
        UniValue out{UniValue::VOBJ};
        out.pushKV("valid", IsFinalTx(CTransaction{tx}, request["height"].getInt<int>(), request["cutoff"].getInt<int64_t>()));
        return out;
    }
    if (op != "contextual_header" && op != "contextual_block" && op != "contextual_block_flags") {
        throw std::runtime_error("unknown oracle operation");
    }
    std::deque<CBlockIndex> history;
    std::vector<uint256> hashes;
    if (request.exists("history")) for (const auto& raw : request["history"].getValues()) {
        const auto header = Header(raw);
        if (!hashes.empty() && header.hashPrevBlock != hashes.back()) throw std::runtime_error("disconnected history");
        history.emplace_back(header);
        hashes.push_back(header.GetHash());
    }
    if (op == "contextual_block_flags") {
        // Adapt the existing explicit-flags API by configuring actual buried
        // deployments and the MTP supplied to the original function.
        const int height = request["height"].getInt<int>();
        if (height < 1) throw std::runtime_error("explicit-cutoff adapter requires height >= 1");
        history.resize(1);
        hashes.resize(1);
        history[0].nHeight = height - 1;
        history[0].nTime = request["cutoff"].getInt<uint32_t>();
        auto& consensus = params.MutableConsensus();
        consensus.CSVHeight = 0;
        consensus.BIP34Height = Bool(request, "enforce_bip34", false) ? 0 : std::numeric_limits<int>::max();
        consensus.SegwitHeight = Bool(request, "expect_witness", false) ? 0 : std::numeric_limits<int>::max();
    }
    if (history.empty()) throw std::runtime_error("context checks require previous history");
    for (size_t i = 0; i < history.size(); ++i) {
        if (op != "contextual_block_flags") history[i].nHeight = i;
        history[i].phashBlock = &hashes[i];
        history[i].pprev = i ? &history[i - 1] : nullptr;
        history[i].BuildSkip();
    }
    kernel::Notifications notifications;
    util::SignalInterrupt interrupt;
    ChainstateManager::Options options{
        .chainparams = params, .datadir = datadir, .notifications = notifications,
        .script_execution_cache_bytes = 0, .signature_cache_bytes = 0,
    };
    BlockManager::Options block_options{
        .chainparams = params, .use_xor = false, .blocks_dir = datadir,
        .notifications = notifications,
        .block_tree_db_params = {.path = datadir / "index", .cache_bytes = 0, .memory_only = true},
    };
    ChainstateManager chainman{interrupt, options, block_options};
    SetMockTime(request.exists("now") ? request["now"].getInt<int64_t>() : 2000000000);
    LOCK(cs_main);
    const auto* previous = &history.back();
    if (op == "contextual_header") {
        const auto header = Header(request["header"], Bool(request, "pure_header", false));
        if (header.hashPrevBlock != previous->GetBlockHash()) throw std::runtime_error("candidate/history mismatch");
        bool valid = ContextualCheckBlockHeader(header, state, chainman.m_blockman, chainman, previous);
        if (valid && Bool(request, "check_pow", false)) valid = CheckBlockHeader(header, state, p, true, previous->nHeight + 1);
        return Verdict(valid, state);
    }
    const auto block = Block(request["block"]);
    if (!CheckBlock(block, state, p, false, true)) return Verdict(false, state);
    if (Bool(request, "check_header", false)) {
        if (block.hashPrevBlock != previous->GetBlockHash()) throw std::runtime_error("candidate/history mismatch");
        if (!ContextualCheckBlockHeader(block, state, chainman.m_blockman, chainman, previous)) return Verdict(false, state);
    }
    const bool valid = ContextualCheckBlock(block, state, chainman, previous);
    return Verdict(valid, state);
}

int main(int argc, char** argv)
{
    try {
        UniValue input;
        if (!input.read(std::string(std::istreambuf_iterator<char>(std::cin), {}))) throw std::runtime_error("invalid request JSON");
        UniValue out{UniValue::VOBJ};
        out.pushKV("revision", ORACLE_NODE_REVISION);
        out.pushKV("validation_sha256", ORACLE_VALIDATION_SHA256);
        UniValue results{UniValue::VARR};
        if (input.exists("requests")) {
            if (argc != 2 || !fs::is_directory(argv[1])) throw std::runtime_error("supply an empty test data directory");
            for (const auto& request : input["requests"].getValues()) {
                try { results.push_back(Run(request, fs::path{argv[1]})); }
                catch (const DecodeError& e) {
                    UniValue rejected{UniValue::VOBJ};
                    rejected.pushKV("decoded", false);
                    rejected.pushKV("decode_error", e.what());
                    results.push_back(rejected);
                }
            }
        }
        out.pushKV("results", results);
        std::cout << out.write() << '\n';
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
