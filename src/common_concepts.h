#pragma once

#include <concepts>
#include <vector>
#include <span>


/// A byte blob such as a std::span<uint8_t> or a std::vector<uint8_t>
template <typename T>
concept ByteBlob = requires (T t)
{
    T(size_t{5u}, typename T::value_type{});
    std::span<uint8_t>{t};
    T().reserve(size_t{1u});
    T().resize(size_t{1u});
    T()[0];
    { T().size() } -> std::convertible_to<size_t>;
};

/// A Hasher. Must support methods .Write(), .Finalize(), .Reset(), and provide a T::OUTPUT_SIZE
template <typename T>
concept Hasher = requires (T t, std::vector<uint8_t> vec)
{
    T();
    { T::OUTPUT_SIZE } -> std::convertible_to<size_t>;
    { t.Write(std::span<const uint8_t>{}) } -> std::same_as<T &>;
    { t.Reset() } -> std::same_as<T &>;
    t.Finalize(std::span<uint8_t, T::OUTPUT_SIZE>{vec});
};
