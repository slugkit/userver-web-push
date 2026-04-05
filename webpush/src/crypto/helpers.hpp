#pragma once

#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <userver/crypto/exception.hpp>

USERVER_NAMESPACE_BEGIN

namespace crypto::impl {

std::string FormatSslError(std::string message);

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct EvpKdfDeleter {
    void operator()(EVP_KDF* p) const noexcept { EVP_KDF_free(p); }
};
using EvpKdfPtr = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;

struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); }
};
using EvpKdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

}  // namespace crypto::impl

USERVER_NAMESPACE_END
