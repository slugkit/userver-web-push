#include <userver/crypto/ecdh.hpp>

#include "helpers.hpp"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>

USERVER_NAMESPACE_BEGIN

namespace crypto::ecdh {

auto GenerateP256() -> EphemeralKeyPair {
    impl::EvpPkeyPtr pkey{EVP_EC_gen("P-256")};
    if (!pkey) {
        throw CryptoException(impl::FormatSslError("Failed to generate P-256 key pair"));
    }

    // Extract uncompressed public key bytes
    std::size_t pubkey_len = 0;
    if (1 != EVP_PKEY_get_octet_string_param(
                 pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pubkey_len
             )) {
        throw CryptoException(impl::FormatSslError("Failed to get public key size"));
    }

    std::string pubkey_raw(pubkey_len, '\0');
    if (1 != EVP_PKEY_get_octet_string_param(
                 pkey.get(),
                 OSSL_PKEY_PARAM_PUB_KEY,
                 reinterpret_cast<unsigned char*>(pubkey_raw.data()),
                 pubkey_raw.size(),
                 &pubkey_len
             )) {
        throw CryptoException(impl::FormatSslError("Failed to extract public key"));
    }
    pubkey_raw.resize(pubkey_len);

    // Export private key as PEM to construct a userver PrivateKey
    auto* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw CryptoException("Failed to create BIO");
    }
    if (1 != PEM_write_bio_PrivateKey(bio, pkey.get(), nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio);
        throw CryptoException(impl::FormatSslError("Failed to export private key as PEM"));
    }
    char* pem_data = nullptr;
    auto pem_len = BIO_get_mem_data(bio, &pem_data);
    auto private_key = PrivateKey::LoadFromString(std::string_view{pem_data, static_cast<std::size_t>(pem_len)});
    BIO_free(bio);

    return EphemeralKeyPair{
        .private_key = std::move(private_key),
        .public_key_raw = std::move(pubkey_raw),
    };
}

auto DeriveSharedSecret(
    const PrivateKey& local,
    std::string_view peer_pubkey_raw
) -> std::string {
    // Load peer public key from raw uncompressed point
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        throw CryptoException("Failed to create OSSL_PARAM_BLD");
    }
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0);
    OSSL_PARAM_BLD_push_octet_string(
        bld,
        OSSL_PKEY_PARAM_PUB_KEY,
        peer_pubkey_raw.data(),
        peer_pubkey_raw.size()
    );
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    if (!params) {
        throw CryptoException(impl::FormatSslError("Failed to build peer key params"));
    }

    impl::EvpPkeyCtxPtr peer_ctx{EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr)};
    if (!peer_ctx) {
        OSSL_PARAM_free(params);
        throw CryptoException(impl::FormatSslError("Failed to create peer key context"));
    }
    if (1 != EVP_PKEY_fromdata_init(peer_ctx.get())) {
        OSSL_PARAM_free(params);
        throw CryptoException(impl::FormatSslError("Failed to init fromdata"));
    }

    EVP_PKEY* peer_raw = nullptr;
    if (1 != EVP_PKEY_fromdata(peer_ctx.get(), &peer_raw, EVP_PKEY_PUBLIC_KEY, params)) {
        OSSL_PARAM_free(params);
        throw CryptoException(impl::FormatSslError("Failed to load peer public key"));
    }
    OSSL_PARAM_free(params);
    impl::EvpPkeyPtr peer_pkey{peer_raw};

    // Derive shared secret
    impl::EvpPkeyCtxPtr derive_ctx{EVP_PKEY_CTX_new(local.GetNative(), nullptr)};
    if (!derive_ctx) {
        throw CryptoException(impl::FormatSslError("Failed to create derive context"));
    }
    if (1 != EVP_PKEY_derive_init(derive_ctx.get())) {
        throw CryptoException(impl::FormatSslError("Failed to init ECDH derive"));
    }
    if (1 != EVP_PKEY_derive_set_peer(derive_ctx.get(), peer_pkey.get())) {
        throw CryptoException(impl::FormatSslError("Failed to set ECDH peer key"));
    }

    std::size_t secret_len = 0;
    if (1 != EVP_PKEY_derive(derive_ctx.get(), nullptr, &secret_len)) {
        throw CryptoException(impl::FormatSslError("Failed to determine shared secret size"));
    }

    std::string secret(secret_len, '\0');
    if (1 != EVP_PKEY_derive(
                 derive_ctx.get(), reinterpret_cast<unsigned char*>(secret.data()), &secret_len
             )) {
        throw CryptoException(impl::FormatSslError("Failed to derive ECDH shared secret"));
    }
    secret.resize(secret_len);
    return secret;
}

}  // namespace crypto::ecdh

USERVER_NAMESPACE_END
