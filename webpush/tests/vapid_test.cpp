#include "webpush/vapid/token.hpp"

#include <userver/crypto/base64.hpp>
#include <userver/crypto/ecdh.hpp>
#include <userver/utest/utest.hpp>

namespace base64 = userver::crypto::base64;

UTEST(WebPushVapid, GeneratesValidAuthHeader) {
    auto kp = userver::crypto::ecdh::GenerateP256();

    // Export private key as PEM
    // GenerateP256 returns a PrivateKey, we need PEM string — use the public API
    // For test, generate via openssl in the keypair
    auto pubkey_b64 = base64::Base64UrlEncode(kp.public_key_raw, base64::Pad::kWithout);

    // We need PEM — extract from the PrivateKey
    auto pem = kp.private_key.GetPemStringUnencrypted();
    ASSERT_TRUE(pem.has_value());

    auto header = webpush::vapid::GenerateAuthHeader(
        "https://fcm.googleapis.com/fcm/send/subscription-id",
        "mailto:test@example.com",
        *pem,
        pubkey_b64
    );

    // Should start with "vapid t="
    EXPECT_EQ(header.substr(0, 8), "vapid t=");

    // Should contain ",k="
    auto k_pos = header.find(",k=");
    ASSERT_NE(k_pos, std::string::npos);

    // JWT part should have 3 dot-separated segments
    auto jwt = header.substr(8, k_pos - 8);
    int dots = 0;
    for (auto c : jwt) {
        if (c == '.') ++dots;
    }
    EXPECT_EQ(dots, 2);

    // Public key part should match what we passed
    auto k_value = header.substr(k_pos + 3);
    EXPECT_EQ(k_value, pubkey_b64);
}
