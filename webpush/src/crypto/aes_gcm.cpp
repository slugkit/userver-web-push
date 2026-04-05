#include <userver/crypto/aes_gcm.hpp>

#include "helpers.hpp"

#include <openssl/evp.h>

USERVER_NAMESPACE_BEGIN

namespace crypto::aes_gcm {

namespace {
constexpr std::size_t kTagSize = 16;
constexpr std::size_t kKeySize128 = 16;
constexpr std::size_t kNonceSize = 12;
}  // namespace

auto Encrypt128(
    std::string_view key,
    std::string_view nonce,
    std::string_view plaintext
) -> std::string {
    if (key.size() != kKeySize128) {
        throw CryptoException("AES-128-GCM key must be 16 bytes");
    }
    if (nonce.size() != kNonceSize) {
        throw CryptoException("AES-128-GCM nonce must be 12 bytes");
    }

    impl::EvpCipherCtxPtr ctx{EVP_CIPHER_CTX_new()};
    if (!ctx) {
        throw CryptoException(impl::FormatSslError("Failed to create cipher context"));
    }

    if (1 != EVP_EncryptInit_ex(
                 ctx.get(),
                 EVP_aes_128_gcm(),
                 nullptr,
                 reinterpret_cast<const unsigned char*>(key.data()),
                 reinterpret_cast<const unsigned char*>(nonce.data())
             )) {
        throw CryptoException(impl::FormatSslError("Failed to init AES-128-GCM encryption"));
    }

    std::string out(plaintext.size() + kTagSize, '\0');
    int out_len = 0;

    if (1 != EVP_EncryptUpdate(
                 ctx.get(),
                 reinterpret_cast<unsigned char*>(out.data()),
                 &out_len,
                 reinterpret_cast<const unsigned char*>(plaintext.data()),
                 static_cast<int>(plaintext.size())
             )) {
        throw CryptoException(impl::FormatSslError("Failed AES-128-GCM EncryptUpdate"));
    }

    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(
                 ctx.get(),
                 reinterpret_cast<unsigned char*>(out.data()) + out_len,
                 &final_len
             )) {
        throw CryptoException(impl::FormatSslError("Failed AES-128-GCM EncryptFinal"));
    }
    out_len += final_len;

    // Append the authentication tag
    if (1 != EVP_CIPHER_CTX_ctrl(
                 ctx.get(),
                 EVP_CTRL_GCM_GET_TAG,
                 kTagSize,
                 reinterpret_cast<unsigned char*>(out.data()) + out_len
             )) {
        throw CryptoException(impl::FormatSslError("Failed to get GCM tag"));
    }

    out.resize(out_len + kTagSize);
    return out;
}

}  // namespace crypto::aes_gcm

USERVER_NAMESPACE_END
