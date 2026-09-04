#include "payload.hpp"

#include <userver/crypto/aes_gcm.hpp>
#include <userver/crypto/base64.hpp>
#include <userver/crypto/ecdh.hpp>
#include <userver/crypto/hkdf.hpp>
#include <userver/crypto/random.hpp>

namespace webpush::encrypt {

namespace {

constexpr std::size_t kSaltSize = 16;
constexpr std::size_t kRecordSize = 4096;
constexpr std::size_t kCekLength = 16;
constexpr std::size_t kNonceLength = 12;
constexpr std::size_t kIkmLength = 32;

/// RFC 8188 §2.2 key-derivation info: the label followed by a single 0x00.
///
/// The 0x01 counter byte that HKDF-Expand appends is NOT part of this — HKDF
/// supplies it. Appending it here too derives the key from
/// "…aes128gcm\0\x01\x01", producing a CEK and nonce no conforming receiver can
/// reproduce, so every browser silently discards the push. Nothing upstream
/// notices: the push service relays without decrypting and answers 201.
///
/// Unlike RFC 8291's key_info, this info carries no public keys.
auto BuildInfo(std::string_view type) -> std::string {
    std::string info = "Content-Encoding: ";
    info += type;
    info += '\0';
    return info;
}

auto BuildIkmInfo(std::string_view subscriber_pubkey, std::string_view server_pubkey) -> std::string {
    std::string info = "WebPush: info";
    info += '\0';
    info.append(subscriber_pubkey.data(), subscriber_pubkey.size());
    info.append(server_pubkey.data(), server_pubkey.size());
    return info;
}

auto PadPayload(std::string_view plaintext) -> std::string {
    std::string padded;
    padded.reserve(plaintext.size() + 1);
    padded.append(plaintext.data(), plaintext.size());
    padded += '\x02';  // RFC 8188 padding delimiter
    return padded;
}

void AppendBigEndian32(std::string& out, std::uint32_t value) {
    out += static_cast<char>((value >> 24) & 0xFF);
    out += static_cast<char>((value >> 16) & 0xFF);
    out += static_cast<char>((value >> 8) & 0xFF);
    out += static_cast<char>(value & 0xFF);
}

}  // namespace

auto EncryptPayload(
    std::string_view plaintext,
    std::string_view subscriber_p256dh,
    std::string_view subscriber_auth
) -> std::string {
    namespace base64 = userver::crypto::base64;
    namespace ecdh = userver::crypto::ecdh;
    namespace hkdf = userver::crypto::hkdf;
    namespace aes_gcm = userver::crypto::aes_gcm;

    // Decode subscriber keys from base64url
    auto subscriber_pubkey = base64::Base64UrlDecode(subscriber_p256dh);
    auto auth_secret = base64::Base64UrlDecode(subscriber_auth);

    // Step 1: Generate ephemeral EC P-256 key pair
    auto ephemeral = ecdh::GenerateP256();

    // Step 2: ECDH shared secret
    auto shared_secret = ecdh::DeriveSharedSecret(ephemeral.private_key, subscriber_pubkey);

    // Step 3: Derive IKM using HKDF with auth secret as salt
    auto ikm_info = BuildIkmInfo(subscriber_pubkey, ephemeral.public_key_raw);
    auto ikm = hkdf::DeriveKey(auth_secret, shared_secret, ikm_info, kIkmLength);

    // Step 4: Generate random salt
    auto salt = userver::crypto::GenerateRandomBlock(kSaltSize);

    // Step 5: Derive content encryption key (CEK) and nonce
    auto cek_info = BuildInfo("aes128gcm");
    auto cek = hkdf::DeriveKey(salt, ikm, cek_info, kCekLength);

    auto nonce_info = BuildInfo("nonce");
    auto nonce = hkdf::DeriveKey(salt, ikm, nonce_info, kNonceLength);

    // Step 6: Pad and encrypt
    auto padded = PadPayload(plaintext);
    auto ciphertext = aes_gcm::Encrypt128(cek, nonce, padded);

    // Step 7: Build aes128gcm body
    // Format: salt(16) || rs(4 big-endian) || keyid_len(1) || server_pubkey(65) || ciphertext+tag
    std::string body;
    body.reserve(kSaltSize + 4 + 1 + ephemeral.public_key_raw.size() + ciphertext.size());
    body.append(salt);
    AppendBigEndian32(body, kRecordSize);
    body += static_cast<char>(ephemeral.public_key_raw.size());
    body.append(ephemeral.public_key_raw);
    body.append(ciphertext);

    return body;
}

}  // namespace webpush::encrypt
