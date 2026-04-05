#pragma once

#include <string>
#include <string_view>

namespace webpush::encrypt {

/// Encrypt a plaintext payload for Web Push (RFC 8291, aes128gcm encoding).
/// @param plaintext The message to encrypt
/// @param subscriber_p256dh Base64url-encoded subscriber public key (65 bytes decoded)
/// @param subscriber_auth Base64url-encoded subscriber auth secret (16 bytes decoded)
/// @returns Full encrypted body including aes128gcm header (salt + rs + keyid + ciphertext)
auto EncryptPayload(
    std::string_view plaintext,
    std::string_view subscriber_p256dh,
    std::string_view subscriber_auth
) -> std::string;

}  // namespace webpush::encrypt
