#pragma once

#include <string>
#include <string_view>

namespace webpush::vapid {

/// Generate a VAPID Authorization header value (RFC 8292).
/// @param endpoint Push service endpoint URL (aud is derived from its origin)
/// @param subject Contact URI (e.g. "mailto:admin@example.com")
/// @param private_key_pem EC P-256 private key PEM
/// @param public_key_b64url Base64url-encoded uncompressed public key
/// @returns Full "vapid t=<jwt>,k=<pubkey>" header value
auto GenerateAuthHeader(
    std::string_view endpoint,
    std::string_view subject,
    std::string_view private_key_pem,
    std::string_view public_key_b64url
) -> std::string;

}  // namespace webpush::vapid
