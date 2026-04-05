#include <userver/crypto/hkdf.hpp>

#include "helpers.hpp"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

USERVER_NAMESPACE_BEGIN

namespace crypto::hkdf {

auto DeriveKey(
    std::string_view salt,
    std::string_view ikm,
    std::string_view info,
    std::size_t length
) -> std::string {
    impl::EvpKdfPtr kdf{EVP_KDF_fetch(nullptr, "HKDF", nullptr)};
    if (!kdf) {
        throw CryptoException(impl::FormatSslError("Failed to fetch HKDF"));
    }

    impl::EvpKdfCtxPtr ctx{EVP_KDF_CTX_new(kdf.get())};
    if (!ctx) {
        throw CryptoException(impl::FormatSslError("Failed to create HKDF context"));
    }

    OSSL_PARAM params[6];
    int idx = 0;

    const char* digest = "SHA256";
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest), 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<char*>(ikm.data()), ikm.size()
    );
    if (!salt.empty()) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<char*>(salt.data()), salt.size()
        );
    }
    if (!info.empty()) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<char*>(info.data()), info.size()
        );
    }
    params[idx] = OSSL_PARAM_construct_end();

    std::string out(length, '\0');
    if (1 != EVP_KDF_derive(
                 ctx.get(), reinterpret_cast<unsigned char*>(out.data()), length, params
             )) {
        throw CryptoException(impl::FormatSslError("Failed to derive HKDF key"));
    }

    return out;
}

}  // namespace crypto::hkdf

USERVER_NAMESPACE_END
