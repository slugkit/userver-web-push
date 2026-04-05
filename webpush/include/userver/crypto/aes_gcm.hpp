#pragma once

/// @file userver/crypto/aes_gcm.hpp
/// @brief AES-GCM authenticated encryption
/// @ingroup userver_universal

#include <string>
#include <string_view>

USERVER_NAMESPACE_BEGIN

namespace crypto::aes_gcm {

/// @brief Encrypt data with AES-128-GCM.
/// @param key 16-byte encryption key
/// @param nonce 12-byte initialization vector
/// @param plaintext Data to encrypt
/// @returns Ciphertext concatenated with 16-byte authentication tag
/// @throws CryptoException on invalid key/nonce size or OpenSSL failure
auto Encrypt128(
    std::string_view key,
    std::string_view nonce,
    std::string_view plaintext
) -> std::string;

}  // namespace crypto::aes_gcm

USERVER_NAMESPACE_END
