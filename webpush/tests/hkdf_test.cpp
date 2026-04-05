#include <userver/crypto/hkdf.hpp>

#include <userver/utest/utest.hpp>

namespace hkdf = userver::crypto::hkdf;

UTEST(CryptoHkdf, ProducesCorrectLength) {
    std::string salt(16, '\x01');
    std::string ikm(32, '\x02');
    std::string info = "test info";

    auto key16 = hkdf::DeriveKey(salt, ikm, info, 16);
    EXPECT_EQ(key16.size(), 16u);

    auto key32 = hkdf::DeriveKey(salt, ikm, info, 32);
    EXPECT_EQ(key32.size(), 32u);

    auto key12 = hkdf::DeriveKey(salt, ikm, info, 12);
    EXPECT_EQ(key12.size(), 12u);
}

UTEST(CryptoHkdf, DeterministicOutput) {
    std::string salt(16, '\xAA');
    std::string ikm(32, '\xBB');
    std::string info = "deterministic";

    auto key1 = hkdf::DeriveKey(salt, ikm, info, 16);
    auto key2 = hkdf::DeriveKey(salt, ikm, info, 16);
    EXPECT_EQ(key1, key2);
}

UTEST(CryptoHkdf, DifferentInfoProducesDifferentKeys) {
    std::string salt(16, '\xCC');
    std::string ikm(32, '\xDD');

    auto key_a = hkdf::DeriveKey(salt, ikm, "info-a", 16);
    auto key_b = hkdf::DeriveKey(salt, ikm, "info-b", 16);
    EXPECT_NE(key_a, key_b);
}

UTEST(CryptoHkdf, EmptySaltWorks) {
    std::string ikm(32, '\xEE');
    auto key = hkdf::DeriveKey("", ikm, "info", 16);
    EXPECT_EQ(key.size(), 16u);
}
