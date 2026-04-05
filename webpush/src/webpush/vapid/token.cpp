#include "token.hpp"

#include <userver/crypto/base64.hpp>
#include <userver/crypto/signers.hpp>
#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value_builder.hpp>
#include <userver/utils/datetime.hpp>

namespace webpush::vapid {

namespace {

constexpr auto kTokenLifetime = std::chrono::hours{12};

auto ExtractOrigin(std::string_view url) -> std::string {
    // Extract scheme + host from URL (e.g. "https://fcm.googleapis.com")
    auto scheme_end = url.find("://");
    if (scheme_end == std::string_view::npos) {
        return std::string{url};
    }
    auto host_start = scheme_end + 3;
    auto path_start = url.find('/', host_start);
    if (path_start == std::string_view::npos) {
        return std::string{url};
    }
    return std::string{url.substr(0, path_start)};
}

auto Base64UrlEncode(std::string_view data) -> std::string {
    return userver::crypto::base64::Base64UrlEncode(data, userver::crypto::base64::Pad::kWithout);
}

}  // namespace

auto GenerateAuthHeader(
    std::string_view endpoint,
    std::string_view subject,
    std::string_view private_key_pem,
    std::string_view public_key_b64url
) -> std::string {
    namespace json = userver::formats::json;

    auto aud = ExtractOrigin(endpoint);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   userver::utils::datetime::Now().time_since_epoch()
    )
                   .count();

    json::ValueBuilder header_builder;
    header_builder["typ"] = "JWT";
    header_builder["alg"] = "ES256";
    auto header = json::ToString(header_builder.ExtractValue());

    json::ValueBuilder claims_builder;
    claims_builder["aud"] = aud;
    claims_builder["sub"] = subject;
    claims_builder["exp"] = now + kTokenLifetime.count();
    auto claims = json::ToString(claims_builder.ExtractValue());

    auto encoded_header = Base64UrlEncode(header);
    auto encoded_claims = Base64UrlEncode(claims);
    auto signing_input = fmt::format("{}.{}", encoded_header, encoded_claims);

    userver::crypto::SignerEs256 signer{std::string{private_key_pem}};
    auto signature_raw = signer.Sign({signing_input});
    auto encoded_signature = Base64UrlEncode(signature_raw);

    auto jwt = fmt::format("{}.{}", signing_input, encoded_signature);
    return fmt::format("vapid t={},k={}", jwt, public_key_b64url);
}

}  // namespace webpush::vapid
