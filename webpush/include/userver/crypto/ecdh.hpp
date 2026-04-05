#pragma once

/// @file userver/crypto/ecdh.hpp
/// @brief Elliptic Curve Diffie-Hellman key agreement (P-256)
/// @ingroup userver_universal

#include <string>
#include <string_view>

#include <userver/crypto/private_key.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto::ecdh {

/// An ephemeral EC P-256 key pair for ECDH key agreement.
struct EphemeralKeyPair {
    PrivateKey private_key;
    std::string public_key_raw;  ///< 65-byte uncompressed P-256 point (0x04 || x || y)
};

/// @brief Generate an ephemeral EC P-256 key pair.
/// @throws CryptoException on OpenSSL failure
auto GenerateP256() -> EphemeralKeyPair;

/// @brief Derive an ECDH shared secret between a local private key and
///        a remote public key given as raw uncompressed P-256 point bytes.
/// @param local Local EC P-256 private key
/// @param peer_pubkey_raw 65-byte uncompressed P-256 public key
/// @returns Raw shared secret bytes
/// @throws CryptoException on OpenSSL failure or invalid key format
auto DeriveSharedSecret(
    const PrivateKey& local,
    std::string_view peer_pubkey_raw
) -> std::string;

}  // namespace crypto::ecdh

USERVER_NAMESPACE_END
