#include <webpush/components/client.hpp>

#include "../encrypt/payload.hpp"
#include "../vapid/token.hpp"

#include <userver/clients/http/client.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/concurrent/variable.hpp>
#include <userver/crypto/hash.hpp>
#include <userver/crypto/signers.hpp>
#include <userver/logging/log.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

#include <chrono>
#include <unordered_map>

namespace webpush {

namespace {

constexpr auto kDefaultRequestTimeout = std::chrono::seconds{10};
// VAPID JWTs are minted with a 12h lifetime; reuse a cached header for a little
// less so it never goes out near-expired.
constexpr auto kVapidCacheTtl = std::chrono::hours{11};

// Encrypt the payload (per-subscription) and POST it with an already-computed
// VAPID Authorization header. The header is the same for every subscription
// sharing the endpoint's origin, so the caller computes it once and caches it.
auto DoSend(
    userver::clients::http::Client& http_client,
    std::string_view auth_header,
    const Notification& notification,
    std::chrono::milliseconds timeout
) -> SendResult {
    if (notification.subscription.endpoint.empty()) {
        return SendResult{.status_code = 400, .reason = "Empty endpoint"};
    }

    // Encrypt payload
    std::string encrypted_body;
    try {
        encrypted_body = encrypt::EncryptPayload(
            notification.payload,
            notification.subscription.p256dh,
            notification.subscription.auth
        );
    } catch (const std::exception& e) {
        LOG_ERROR() << "Web Push encryption failed: " << e.what();
        return SendResult{.status_code = 0, .reason = e.what()};
    }

    std::shared_ptr<userver::clients::http::Response> response;
    try {
        response = http_client.CreateRequest()
                       .post(notification.subscription.endpoint, encrypted_body)
                       .headers({
                           {"Authorization", std::string{auth_header}},
                           {"Content-Encoding", "aes128gcm"},
                           {"Content-Type", "application/octet-stream"},
                           {"TTL", std::to_string(notification.ttl)},
                       })
                       .timeout(timeout)
                       .perform();
    } catch (const std::exception& e) {
        LOG_ERROR() << "Web Push request failed: " << e.what();
        return SendResult{.status_code = 0, .reason = e.what()};
    }

    auto status = static_cast<std::int32_t>(response->status_code());

    std::string reason;
    if (status != 201 && status != 200) {
        auto body = response->body();
        LOG_WARNING() << "Web Push error: status=" << status << ", body=" << body;
        reason = body;
    }

    return SendResult{
        .status_code = status,
        .reason = std::move(reason),
    };
}

// Stable cache key for a VAPID header: the endpoint origin (the JWT `aud`) plus
// the credential. Includes the private key so a rotated key gets a fresh token;
// hashed, so no key material is retained.
auto HeaderCacheKey(std::string_view origin, const Credentials& creds) -> std::string {
    return userver::crypto::hash::Sha256(
        std::string{origin} + '\n' + creds.subject + '\n' + creds.public_key + '\n' + creds.private_key_pem
    );
}

}  // namespace

struct Client::Impl {
    userver::components::HttpClient& http_client;
    Credentials credentials;
    std::chrono::milliseconds request_timeout;

    // Per-(origin, credential) VAPID header cache for the multi-tenant
    // Send(creds, ...) path: re-signing a VAPID JWT for every send is wasted
    // CPU, and one header is valid for all subscriptions sharing an origin
    // (e.g. every fcm.googleapis.com endpoint). Keyed by HeaderCacheKey.
    struct CachedHeader {
        std::string header;
        std::chrono::steady_clock::time_point deadline;
    };
    mutable userver::concurrent::Variable<std::unordered_map<std::string, CachedHeader>> header_cache;

    Impl(
        const userver::components::ComponentConfig& config,
        const userver::components::ComponentContext& context
    )
        : http_client(context.FindComponent<userver::components::HttpClient>())
        , credentials(Credentials::FromConfig(config))
        , request_timeout(config["request-timeout"].As<std::chrono::milliseconds>(kDefaultRequestTimeout)) {
        // The default credential is optional: a consumer that only ever calls
        // the per-credential Send(creds, ...) overload (e.g. a multi-tenant
        // dispatcher with per-app VAPID keys) can register the client with no
        // private-key-pem/public-key/subject and skip validation entirely.
        const bool has_default_credential = !credentials.private_key_pem.empty() || !credentials.public_key.empty() ||
                                            !credentials.subject.empty();
        if (!has_default_credential) {
            LOG_INFO() << "webpush-client: no default credential configured; per-credential Send only";
            return;
        }

        // When any default field is set, all three are required.
        if (credentials.private_key_pem.empty()) {
            throw std::runtime_error("webpush-client: private-key-pem is not configured (set VAPID_PRIVATE_KEY_PEM)");
        }
        if (credentials.public_key.empty()) {
            throw std::runtime_error("webpush-client: public-key is not configured (set VAPID_PUBLIC_KEY)");
        }
        if (credentials.subject.empty()) {
            throw std::runtime_error("webpush-client: subject is not configured (set VAPID_SUBJECT)");
        }
        try {
            userver::crypto::SignerEs256{credentials.private_key_pem};
        } catch (const std::exception& e) {
            throw std::runtime_error(fmt::format("webpush-client: invalid private-key-pem: {}", e.what()));
        }
    }

    auto Send(const Notification& notification) const -> SendResult {
        return Send(credentials, notification);
    }

    auto Send(const Credentials& creds, const Notification& notification) const -> SendResult {
        if (notification.subscription.endpoint.empty()) {
            return SendResult{.status_code = 400, .reason = "Empty endpoint"};
        }
        std::string auth_header;
        try {
            auth_header = AuthHeaderFor(creds, notification.subscription.endpoint);
        } catch (const std::exception& e) {
            LOG_ERROR() << "VAPID token generation failed: " << e.what();
            return SendResult{.status_code = 0, .reason = e.what()};
        }
        return DoSend(http_client.GetHttpClient(), auth_header, notification, request_timeout);
    }

    // Return a cached VAPID Authorization header for this credential + endpoint
    // origin, minting (and caching) a fresh one on a miss or near-expiry.
    auto AuthHeaderFor(const Credentials& creds, std::string_view endpoint) const -> std::string {
        const auto origin = vapid::ExtractOrigin(endpoint);
        const auto key = HeaderCacheKey(origin, creds);
        const auto now = std::chrono::steady_clock::now();
        {
            auto cache = header_cache.Lock();
            auto it = cache->find(key);
            if (it != cache->end() && now < it->second.deadline) {
                return it->second.header;
            }
        }

        auto header = vapid::GenerateAuthHeader(endpoint, creds.subject, creds.private_key_pem, creds.public_key);
        const auto deadline = now + kVapidCacheTtl;
        {
            auto cache = header_cache.Lock();
            // Drop expired entries so the map stays bounded by the live origin set.
            std::erase_if(*cache, [&](const auto& kv) { return now >= kv.second.deadline; });
            (*cache)[key] = CachedHeader{header, deadline};
        }
        return header;
    }
};

Client::Client(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context
)
    : userver::components::ComponentBase(config, context)
    , impl_{config, context} {}

Client::~Client() = default;

auto Client::GetStaticConfigSchema() -> userver::yaml_config::Schema {
    return userver::yaml_config::MergeSchemas<userver::components::ComponentBase>(R"(
type: object
description: Web Push notification client (VAPID)
additionalProperties: false
properties:
    private-key-pem:
        type: string
        description: EC P-256 private key PEM for VAPID signing
    public-key:
        type: string
        description: Base64url-encoded uncompressed P-256 public key
    subject:
        type: string
        description: 'Contact URI (mailto: or https:)'
    request-timeout:
        type: string
        description: HTTP request timeout
        defaultDescription: 10s
    )");
}

auto Client::Send(const Notification& notification) const -> SendResult {
    return impl_->Send(notification);
}

auto Client::Send(const Credentials& credentials, const Notification& notification) const -> SendResult {
    return impl_->Send(credentials, notification);
}

}  // namespace webpush
