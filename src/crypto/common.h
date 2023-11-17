// Copyright (c) 2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#if defined(HAVE_CONFIG_H)
#include <config/config.h>
#endif

#include <cstdint>
#include <cstring>

#include <compat/endian.h>

inline uint16_t ReadLE16(const uint8_t *ptr) {
    uint16_t x;
    std::memcpy(&x, ptr, 2);
    return le16toh(x);
}

inline uint32_t ReadLE32(const uint8_t *ptr) {
    uint32_t x;
    std::memcpy(&x, ptr, 4);
    return le32toh(x);
}

inline uint64_t ReadLE64(const uint8_t *ptr) {
    uint64_t x;
    std::memcpy(&x, ptr, 8);
    return le64toh(x);
}

inline void WriteLE16(uint8_t *ptr, uint16_t x) {
    uint16_t v = htole16(x);
    std::memcpy(ptr, &v, 2);
}

inline void WriteLE32(uint8_t *ptr, uint32_t x) {
    uint32_t v = htole32(x);
    std::memcpy(ptr, &v, 4);
}

inline void WriteLE64(uint8_t *ptr, uint64_t x) {
    uint64_t v = htole64(x);
    std::memcpy(ptr, &v, 8);
}

inline uint16_t ReadBE16(const uint8_t *ptr) {
    uint16_t x;
    std::memcpy(&x, ptr, 2);
    return be16toh(x);
}

inline uint32_t ReadBE32(const uint8_t *ptr) {
    uint32_t x;
    std::memcpy(&x, ptr, 4);
    return be32toh(x);
}

inline uint64_t ReadBE64(const uint8_t *ptr) {
    uint64_t x;
    std::memcpy(&x, ptr, 8);
    return be64toh(x);
}

inline void WriteBE32(uint8_t *ptr, uint32_t x) {
    uint32_t v = htobe32(x);
    std::memcpy(ptr, &v, 4);
}

inline void WriteBE64(uint8_t *ptr, uint64_t x) {
    uint64_t v = htobe64(x);
    std::memcpy(ptr, &v, 8);
}

/**
 * Return the smallest number n such that (x >> n) == 0 (or 64 if the highest
 * bit in x is set.
 */
inline uint64_t CountBits(uint64_t x) {
#ifdef HAVE_DECL___BUILTIN_CLZL
    if constexpr (sizeof(unsigned long) >= sizeof(uint64_t)) {
        return x ? static_cast<uint64_t>(8 * sizeof(unsigned long) - __builtin_clzl(x)) : 0u;
    }
#endif
#ifdef HAVE_DECL___BUILTIN_CLZLL
    if constexpr (sizeof(unsigned long long) >= sizeof(uint64_t)) {
        return x ? static_cast<uint64_t>(8 * sizeof(unsigned long long) - __builtin_clzll(x)) : 0u;
    }
#endif
    uint64_t ret = 0u;
    while (x) {
        x >>= 1u;
        ++ret;
    }
    return ret;
}
