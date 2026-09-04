/// End-to-end check that what we encrypt is what a browser can decrypt.
///
/// The other encryption tests assert the *shape* of the output — header
/// lengths, that two calls differ. Those pass just as happily on a payload no
/// receiver can open, which is exactly the failure that reached production: the
/// push service relays without decrypting and answers 201, the browser fails to
/// decrypt and silently discards, and nothing anywhere reports an error.
///
/// So the receiver here is written straight from RFC 8291 §3.4 and RFC 8188
/// §2.2 against OpenSSL, deliberately NOT reusing the crypto helpers the
/// encryptor uses. A test that shares the implementation's assumptions cannot
/// catch the implementation being wrong about them.

#include "../src/webpush/encrypt/payload.hpp"

#include <userver/crypto/base64.hpp>
#include <userver/utest/utest.hpp>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

namespace base64 = userver::crypto::base64;

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;

/// A stand-in for the browser: a P-256 keypair plus a 16-byte auth secret.
struct Subscriber {
    PkeyPtr keypair;
    std::string p256dh_b64url;
    std::string auth_b64url;
    std::string auth_raw;
};

auto GenerateSubscriber() -> Subscriber {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    EVP_PKEY_keygen_init(ctx.get());
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1);
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) throw std::runtime_error("subscriber keygen failed");
    PkeyPtr keypair{raw};

    std::vector<unsigned char> point(65);
    std::size_t point_len = 0;
    if (EVP_PKEY_get_octet_string_param(
            keypair.get(), "pub", point.data(), point.size(), &point_len
        ) != 1) {
        throw std::runtime_error("failed to export subscriber public key");
    }

    std::string auth_raw(16, '\0');
    for (std::size_t i = 0; i < auth_raw.size(); ++i) auth_raw[i] = static_cast<char>(i * 7 + 3);

    return Subscriber{
        .keypair = std::move(keypair),
        .p256dh_b64url = base64::Base64UrlEncode(
            std::string_view{reinterpret_cast<const char*>(point.data()), point_len}, base64::Pad::kWithout
        ),
        .auth_b64url = base64::Base64UrlEncode(auth_raw, base64::Pad::kWithout),
        .auth_raw = auth_raw,
    };
}

auto Hkdf(std::string_view salt, std::string_view ikm, std::string_view info, std::size_t length)
    -> std::string {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> ctx{
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr)
    };
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) throw std::runtime_error("hkdf init");
    EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(
        ctx.get(), reinterpret_cast<const unsigned char*>(salt.data()), static_cast<int>(salt.size())
    );
    EVP_PKEY_CTX_set1_hkdf_key(
        ctx.get(), reinterpret_cast<const unsigned char*>(ikm.data()), static_cast<int>(ikm.size())
    );
    EVP_PKEY_CTX_add1_hkdf_info(
        ctx.get(), reinterpret_cast<const unsigned char*>(info.data()), static_cast<int>(info.size())
    );
    std::string out(length, '\0');
    std::size_t out_len = length;
    if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char*>(out.data()), &out_len) <= 0) {
        throw std::runtime_error("hkdf derive");
    }
    return out;
}

auto EcdhSecret(EVP_PKEY& own, std::string_view peer_point) -> std::string {
    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> pctx{
        EVP_PKEY_CTX_new_from_pkey(nullptr, &own, nullptr)
    };
    EVP_PKEY* peer_raw = EVP_PKEY_new();
    EVP_PKEY_copy_parameters(peer_raw, &own);
    if (EVP_PKEY_set1_encoded_public_key(
            peer_raw, reinterpret_cast<const unsigned char*>(peer_point.data()), peer_point.size()
        ) != 1) {
        EVP_PKEY_free(peer_raw);
        throw std::runtime_error("failed to load peer public key");
    }
    PkeyPtr peer{peer_raw};

    std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter> ctx{EVP_PKEY_CTX_new(&own, nullptr)};
    if (EVP_PKEY_derive_init(ctx.get()) <= 0) throw std::runtime_error("ecdh init");
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) <= 0) throw std::runtime_error("ecdh peer");
    std::size_t len = 0;
    EVP_PKEY_derive(ctx.get(), nullptr, &len);
    std::string secret(len, '\0');
    if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char*>(secret.data()), &len) <= 0) {
        throw std::runtime_error("ecdh derive");
    }
    secret.resize(len);
    return secret;
}

/// Decrypt an aes128gcm Web Push body the way a browser does.
auto Decrypt(std::string_view body, const Subscriber& subscriber) -> std::string {
    if (body.size() < 21) throw std::runtime_error("body too short for an aes128gcm header");

    const auto salt = body.substr(0, 16);
    const auto idlen = static_cast<std::uint8_t>(body[20]);
    const auto as_public = body.substr(21, idlen);
    const auto ciphertext = body.substr(21 + idlen);
    if (ciphertext.size() < 16) throw std::runtime_error("ciphertext shorter than the GCM tag");

    std::vector<unsigned char> ua_point(65);
    std::size_t ua_len = 0;
    EVP_PKEY_get_octet_string_param(
        subscriber.keypair.get(), "pub", ua_point.data(), ua_point.size(), &ua_len
    );
    const std::string ua_public{reinterpret_cast<const char*>(ua_point.data()), ua_len};

    const auto shared = EcdhSecret(*subscriber.keypair, as_public);

    // RFC 8291 §3.4
    std::string key_info = "WebPush: info";
    key_info += '\0';
    key_info += ua_public;
    key_info += as_public;
    const auto ikm = Hkdf(subscriber.auth_raw, shared, key_info, 32);

    // RFC 8188 §2.2 — label + 0x00. HKDF-Expand appends the 0x01 counter.
    std::string cek_info = "Content-Encoding: aes128gcm";
    cek_info += '\0';
    std::string nonce_info = "Content-Encoding: nonce";
    nonce_info += '\0';
    const auto cek = Hkdf(salt, ikm, cek_info, 16);
    const auto nonce = Hkdf(salt, ikm, nonce_info, 12);

    const auto tag = ciphertext.substr(ciphertext.size() - 16);
    const auto data = ciphertext.substr(0, ciphertext.size() - 16);

    std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter> ctx{EVP_CIPHER_CTX_new()};
    EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr);
    EVP_DecryptInit_ex(
        ctx.get(), nullptr, nullptr,
        reinterpret_cast<const unsigned char*>(cek.data()),
        reinterpret_cast<const unsigned char*>(nonce.data())
    );

    std::string plaintext(data.size(), '\0');
    int out_len = 0;
    EVP_DecryptUpdate(
        ctx.get(), reinterpret_cast<unsigned char*>(plaintext.data()), &out_len,
        reinterpret_cast<const unsigned char*>(data.data()), static_cast<int>(data.size())
    );
    EVP_CIPHER_CTX_ctrl(
        ctx.get(), EVP_CTRL_GCM_SET_TAG, 16, const_cast<char*>(tag.data())
    );
    int final_len = 0;
    if (EVP_DecryptFinal_ex(
            ctx.get(), reinterpret_cast<unsigned char*>(plaintext.data()) + out_len, &final_len
        ) != 1) {
        throw std::runtime_error("GCM authentication failed — the receiver cannot open this payload");
    }
    plaintext.resize(static_cast<std::size_t>(out_len + final_len));

    // Strip the RFC 8188 record delimiter.
    while (!plaintext.empty() && plaintext.back() == '\0') plaintext.pop_back();
    if (!plaintext.empty() && (plaintext.back() == '\x02' || plaintext.back() == '\x01')) {
        plaintext.pop_back();
    }
    return plaintext;
}

}  // namespace

UTEST(WebPushDecryptRoundtrip, AConformingReceiverCanOpenWhatWeEncrypt) {
    const auto subscriber = GenerateSubscriber();
    const std::string plaintext = R"({"v":1,"title":"Hello","body":"from poke-me"})";

    const auto body =
        webpush::encrypt::EncryptPayload(plaintext, subscriber.p256dh_b64url, subscriber.auth_b64url);

    EXPECT_EQ(Decrypt(body, subscriber), plaintext);
}

UTEST(WebPushDecryptRoundtrip, SurvivesAnEmptyAndALargePayload) {
    const auto subscriber = GenerateSubscriber();

    const auto empty = webpush::encrypt::EncryptPayload("", subscriber.p256dh_b64url, subscriber.auth_b64url);
    EXPECT_EQ(Decrypt(empty, subscriber), "");

    const std::string large(3000, 'x');
    const auto big = webpush::encrypt::EncryptPayload(large, subscriber.p256dh_b64url, subscriber.auth_b64url);
    EXPECT_EQ(Decrypt(big, subscriber), large);
}

UTEST(WebPushDecryptRoundtrip, EachSubscriberGetsItsOwnKeys) {
    const auto a = GenerateSubscriber();
    const auto b = GenerateSubscriber();
    const auto body = webpush::encrypt::EncryptPayload("for a only", a.p256dh_b64url, a.auth_b64url);

    EXPECT_EQ(Decrypt(body, a), "for a only");
    EXPECT_THROW(Decrypt(body, b), std::runtime_error);
}
