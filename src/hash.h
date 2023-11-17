#pragma once

#include "common_concepts.h"
#include "crypto/sha256.h"

/// A generic double hasher. Hashes data, then hashes the result. Used to implement e.g. Sha256D.
template <Hasher T>
class DoubleHasher {
    T hasher;

public:
    static constexpr size_t OUTPUT_SIZE = T::OUTPUT_SIZE;

    void Finalize(std::span<uint8_t, OUTPUT_SIZE> output) {
        hasher.Finalize(output);
        hasher.Reset().Write(output).Finalize(output);
    }

    void Finalize(std::span<uint8_t> output) {
        /* dynamic extent, check size at runtime */
        assert(output.size() == OUTPUT_SIZE);
        Finalize(std::span<uint8_t, OUTPUT_SIZE>{output});
    }

    DoubleHasher & Write(std::span<const uint8_t> input) {
        hasher.Write(input);
        return *this;
    }

    DoubleHasher & Reset() {
        hasher.Reset();
        return *this;
    }
};

/** A hasher class for Bitcoin's 256-bit hash (double SHA-256). */
using Sha256D = DoubleHasher<Sha256>;

/// Applies Hasher h to `data`, returning the result. Default is to do a Sha256D.
template <ByteBlob Ret = std::vector<uint8_t>, Hasher H = Sha256D>
inline Ret Hash(std::span<const uint8_t> data) {
    Ret ret(H::OUTPUT_SIZE, typename Ret::value_type(0));
    H().Write(data).Finalize(std::span<uint8_t, Sha256D::OUTPUT_SIZE>{ret});
    return ret;
}
