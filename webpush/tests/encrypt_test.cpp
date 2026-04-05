#include "webpush/encrypt/payload.hpp"

#include <userver/crypto/base64.hpp>
#include <userver/crypto/ecdh.hpp>
#include <userver/utest/utest.hpp>

namespace base64 = userver::crypto::base64;

UTEST(WebPushEncrypt, ProducesValidAes128gcmFormat) {
    // Generate a subscriber key pair (simulating browser)
    auto subscriber = userver::crypto::ecdh::GenerateP256();
    auto subscriber_p256dh = base64::Base64UrlEncode(subscriber.public_key_raw, base64::Pad::kWithout);

    // Generate 16-byte auth secret
    std::string auth_secret(16, '\xAB');
    auto subscriber_auth = base64::Base64UrlEncode(auth_secret, base64::Pad::kWithout);

    std::string plaintext = R"({"title":"Test","body":"Hello"})";

    auto encrypted = webpush::encrypt::EncryptPayload(plaintext, subscriber_p256dh, subscriber_auth);

    // Verify aes128gcm header structure
    ASSERT_GE(encrypted.size(), 16u + 4u + 1u + 65u);  // salt + rs + keyid_len + pubkey minimum

    // Salt: first 16 bytes
    // Record size: next 4 bytes (big-endian)
    auto rs = static_cast<std::uint32_t>(
        (static_cast<unsigned char>(encrypted[16]) << 24) | (static_cast<unsigned char>(encrypted[17]) << 16) |
        (static_cast<unsigned char>(encrypted[18]) << 8) | static_cast<unsigned char>(encrypted[19])
    );
    EXPECT_EQ(rs, 4096u);

    // Key ID length
    auto keyid_len = static_cast<unsigned char>(encrypted[20]);
    EXPECT_EQ(keyid_len, 65u);

    // Server public key starts with 0x04 (uncompressed point)
    EXPECT_EQ(static_cast<unsigned char>(encrypted[21]), 0x04);

    // Total: header (86 bytes) + encrypted payload
    auto header_size = 16 + 4 + 1 + 65;
    EXPECT_GT(encrypted.size(), static_cast<std::size_t>(header_size));
}

UTEST(WebPushEncrypt, DifferentCallsProduceDifferentOutput) {
    auto subscriber = userver::crypto::ecdh::GenerateP256();
    auto p256dh = base64::Base64UrlEncode(subscriber.public_key_raw, base64::Pad::kWithout);
    std::string auth_secret(16, '\xCD');
    auto auth = base64::Base64UrlEncode(auth_secret, base64::Pad::kWithout);

    auto enc1 = webpush::encrypt::EncryptPayload("hello", p256dh, auth);
    auto enc2 = webpush::encrypt::EncryptPayload("hello", p256dh, auth);

    // Different ephemeral keys and salts each time
    EXPECT_NE(enc1, enc2);
}
