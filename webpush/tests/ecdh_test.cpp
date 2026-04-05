#include <userver/crypto/ecdh.hpp>

#include <userver/utest/utest.hpp>

namespace ecdh = userver::crypto::ecdh;

UTEST(CryptoEcdh, GenerateP256ProducesValidKeyPair) {
    auto kp = ecdh::GenerateP256();

    // Uncompressed P-256 point is always 65 bytes (0x04 || 32-byte x || 32-byte y)
    EXPECT_EQ(kp.public_key_raw.size(), 65u);
    EXPECT_EQ(static_cast<unsigned char>(kp.public_key_raw[0]), 0x04);
}

UTEST(CryptoEcdh, TwoKeyPairsDiffer) {
    auto kp1 = ecdh::GenerateP256();
    auto kp2 = ecdh::GenerateP256();
    EXPECT_NE(kp1.public_key_raw, kp2.public_key_raw);
}

UTEST(CryptoEcdh, SharedSecretIsSymmetric) {
    auto alice = ecdh::GenerateP256();
    auto bob = ecdh::GenerateP256();

    auto secret_ab = ecdh::DeriveSharedSecret(alice.private_key, bob.public_key_raw);
    auto secret_ba = ecdh::DeriveSharedSecret(bob.private_key, alice.public_key_raw);

    EXPECT_EQ(secret_ab, secret_ba);
    EXPECT_EQ(secret_ab.size(), 32u);  // P-256 shared secret is 32 bytes
}

UTEST(CryptoEcdh, DifferentPeersProduceDifferentSecrets) {
    auto alice = ecdh::GenerateP256();
    auto bob = ecdh::GenerateP256();
    auto carol = ecdh::GenerateP256();

    auto secret_ab = ecdh::DeriveSharedSecret(alice.private_key, bob.public_key_raw);
    auto secret_ac = ecdh::DeriveSharedSecret(alice.private_key, carol.public_key_raw);

    EXPECT_NE(secret_ab, secret_ac);
}
