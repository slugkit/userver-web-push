#include <userver/crypto/aes_gcm.hpp>

#include <userver/crypto/exception.hpp>
#include <userver/utest/utest.hpp>

namespace aes_gcm = userver::crypto::aes_gcm;

UTEST(CryptoAesGcm, EncryptProducesOutput) {
    std::string key(16, '\x01');
    std::string nonce(12, '\x02');
    std::string plaintext = "Hello, Web Push!";

    auto ciphertext = aes_gcm::Encrypt128(key, nonce, plaintext);

    // Ciphertext = encrypted data (same length as plaintext) + 16-byte tag
    EXPECT_EQ(ciphertext.size(), plaintext.size() + 16u);
}

UTEST(CryptoAesGcm, DifferentNoncesProduceDifferentCiphertext) {
    std::string key(16, '\x01');
    std::string nonce1(12, '\x02');
    std::string nonce2(12, '\x03');
    std::string plaintext = "Same plaintext";

    auto ct1 = aes_gcm::Encrypt128(key, nonce1, plaintext);
    auto ct2 = aes_gcm::Encrypt128(key, nonce2, plaintext);
    EXPECT_NE(ct1, ct2);
}

UTEST(CryptoAesGcm, DeterministicWithSameInputs) {
    std::string key(16, '\xAA');
    std::string nonce(12, '\xBB');
    std::string plaintext = "Deterministic test";

    auto ct1 = aes_gcm::Encrypt128(key, nonce, plaintext);
    auto ct2 = aes_gcm::Encrypt128(key, nonce, plaintext);
    EXPECT_EQ(ct1, ct2);
}

UTEST(CryptoAesGcm, ThrowsOnInvalidKeySize) {
    std::string bad_key(15, '\x01');  // wrong size
    std::string nonce(12, '\x02');
    EXPECT_THROW(aes_gcm::Encrypt128(bad_key, nonce, "data"), userver::crypto::CryptoException);
}

UTEST(CryptoAesGcm, ThrowsOnInvalidNonceSize) {
    std::string key(16, '\x01');
    std::string bad_nonce(11, '\x02');  // wrong size
    EXPECT_THROW(aes_gcm::Encrypt128(key, bad_nonce, "data"), userver::crypto::CryptoException);
}

UTEST(CryptoAesGcm, EmptyPlaintext) {
    std::string key(16, '\x01');
    std::string nonce(12, '\x02');

    auto ciphertext = aes_gcm::Encrypt128(key, nonce, "");
    EXPECT_EQ(ciphertext.size(), 16u);  // just the tag
}
