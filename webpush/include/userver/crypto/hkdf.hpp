#pragma once

/// @file userver/crypto/hkdf.hpp
/// @brief HKDF-SHA256 key derivation (RFC 5869)
/// @ingroup userver_universal

#include <cstddef>
#include <string>
#include <string_view>

USERVER_NAMESPACE_BEGIN

namespace crypto::hkdf {

/// @brief Derive a key using HKDF-SHA256.
/// @param salt Optional salt (can be empty for zero-length salt)
/// @param ikm Input keying material
/// @param info Context/application-specific info string
/// @param length Desired output length in bytes
/// @returns Derived key bytes
/// @throws CryptoException on OpenSSL failure
auto DeriveKey(
    std::string_view salt,
    std::string_view ikm,
    std::string_view info,
    std::size_t length
) -> std::string;

}  // namespace crypto::hkdf

USERVER_NAMESPACE_END
