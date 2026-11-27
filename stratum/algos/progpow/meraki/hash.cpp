// Meraki (Telestai Progpow) light-verifier integration for Yiimp stratum.
// The vendored C++ implementation lives in meraki/lib/ and is derived from
// Miningcore's Native/libmeraki. Its symbols are renamed so it can coexist
// with the existing Ethash/Kawpow/Firo objects in the same binary.

#include "stratum.h"
#include "hash.h"
#include "helpers.hpp"
#include "algos/progpow/meraki/lib/meraki/progpow.hpp"

#include <cmath>

std::vector<meraki_coin_context*> meraki_contexts;

int meraki_epoch_for_height(int height)
{
    return height > 0 ? height / MERAKI_EPOCH_LENGTH : 0;
}

uint256 meraki_epoch_seed(int height)
{
    const auto seed = meraki::calculate_epoch_seed(meraki_epoch_for_height(height));
    return uint256S(meraki_to_hex(seed));
}

uint256 meraki_diff_to_target(double difficulty)
{
    if (!(difficulty > 0.0) || !std::isfinite(difficulty))
        return uint256{};

    uint256 firo_target;
    diff_to_target(firo_target, difficulty);

    // Telestai Diff1 is 00000000ff00..., while diff_to_target() uses the
    // Firo-scale 0000ffff0000...: Firo Diff1 = Telestai Diff1 * 257/256.
    // Clamp rather than wrap when the Firo target is already near 2^256.
    const arith_uint256 max_target = ~arith_uint256(0);
    arith_uint256 target = UintToArith256(firo_target);
    if (target > (max_target >> 8))
        return ArithToUint256(max_target);

    return ArithToUint256((target << 8) / arith_uint256(257));
}

double meraki_target_to_diff(uint256& target)
{
    if (target.IsNull()) return 0;

    arith_uint256 base_hash;
    base_hash.SetHex("00000000ff0000000000000000000000000000000000000000000000000000");
    return base_hash.getdouble() / UintToArith256(target).getdouble();
}

void meraki_update_epoch(const int coinid, int& height)
{
    CommonLock(&g_context_mutex);

    for (auto& item : meraki_contexts) {
        if (item->id == coinid) {
            if (item->height == height) {
                CommonUnlock(&g_context_mutex);
                return;
            }

            const auto epoch_number = meraki_epoch_for_height(height);
            if (!item->context || item->context->epoch_number != epoch_number) {
                if (item->previous && item->previous->epoch_number == epoch_number)
                    std::swap(item->context, item->previous);
                else {
                    item->previous = item->context;
                    item->context = meraki_context_ptr(meraki::create_epoch_context(epoch_number));
                }
            }

            item->height = height;
            CommonUnlock(&g_context_mutex);
            return;
        }
    }

    const auto epoch_number = meraki_epoch_for_height(height);
    auto* item = new meraki_coin_context {
        coinid, height, meraki_context_ptr(meraki::create_epoch_context(epoch_number)), nullptr
    };
    meraki_contexts.push_back(item);

    CommonUnlock(&g_context_mutex);
}

// context of this coin for an epoch (current or previous), held by the caller
static meraki_context_ptr meraki_context_for(const int coinid, int epoch_number)
{
    meraki_context_ptr found;
    CommonLock(&g_context_mutex);
    for (auto& item : meraki_contexts) {
        if (item->id != coinid) continue;
        if (item->context && item->context->epoch_number == epoch_number) found = item->context;
        else if (item->previous && item->previous->epoch_number == epoch_number) found = item->previous;
        else if (item->context) found = item->context;	// coin known, other epoch
        break;
    }
    CommonUnlock(&g_context_mutex);
    return found;
}

uint256 meraki_fullhash(uint256& header_hash, uint64_t& header_nonce,
    uint256& mix_hash, int& coinid, int height)
{
    // ProgPoW folds block_number/3 into the mix seed: verify with the height
    // (and epoch) of the job the share was submitted for
    const int epoch_number = meraki_epoch_for_height(height);
    meraki_context_ptr context = meraki_context_for(coinid, epoch_number);
    if (!context)
        return badhash;
    if (context->epoch_number != epoch_number)
        return badhash;	// job older than the previous epoch

    const auto hash = to_meraki_hash256(header_hash.ToString());
    const auto result = meraki_progpow::meraki_progpow_hash(
        *context, height, hash, header_nonce);
    mix_hash = uint256S(meraki_to_hex(result.mix_hash));

    return uint256S(meraki_to_hex(result.final_hash));
}

uint256 meraki_hash(const std::string& header_hash, const std::string& header_nonce,
    std::string& mix_real, int& coinid, int height)
{
    uint256 mix_hash;
    uint256 header = uint256S(header_hash);
    uint64_t nonce = strtoull(header_nonce.c_str(), NULL, 16);
    uint256 result_hash = meraki_fullhash(header, nonce, mix_hash, coinid, height);

    mix_real = mix_hash.ToString();
    return result_hash;
}
