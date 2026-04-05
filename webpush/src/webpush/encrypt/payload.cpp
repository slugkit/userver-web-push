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

auto BuildInfo(std::string_view type, std::string_view subscriber_pubkey, std::string_view server_pubkey)
    -> std::string {
    // "Content-Encoding: <type>\0\1"
    std::string info = "Content-Encoding: ";
    info += type;
    info += '\0';
    info += '\1';
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
    auto cek_info = BuildInfo("aes128gcm", subscriber_pubkey, ephemeral.public_key_raw);
    auto cek = hkdf::DeriveKey(salt, ikm, cek_info, kCekLength);

    auto nonce_info = BuildInfo("nonce", subscriber_pubkey, ephemeral.public_key_raw);
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
