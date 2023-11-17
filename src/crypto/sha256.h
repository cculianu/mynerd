// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2016-2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cassert>
#include <cstdint>
#include <span>
#include <string>

/** A hasher class for SHA-256. */
class Sha256 {
    uint32_t s[8];
    uint8_t buf[64];
    uint64_t bytes;

public:
    static constexpr size_t OUTPUT_SIZE = 32;

    Sha256();

    Sha256 & Write(std::span<const uint8_t> data);
    void Finalize(std::span<uint8_t, OUTPUT_SIZE> hash);
    void Finalize(std::span<uint8_t> hash) {
        /* dynamic extent, check size at runtime */
        assert(hash.size() == OUTPUT_SIZE);
        Finalize(std::span<uint8_t, OUTPUT_SIZE>{hash});
    }
    Sha256 & Reset();
};

/**
 * On app startup, we autodetect the best available SHA256
 * implementation. This returns the name of the implementation.
 */
extern const std::string & GetSha256Implementation();

/**
 * Compute multiple double-SHA256's of 64-byte blobs.
 * output:  pointer to a blocks*32 byte output buffer
 * input:   pointer to a blocks*64 byte input buffer
 * blocks:  the number of hashes to compute.
 */
extern void Sha256D64(uint8_t *output, const uint8_t *input, size_t blocks);
