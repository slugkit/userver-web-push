#include <webpush/components/client.hpp>

#include "../encrypt/payload.hpp"
#include "../vapid/token.hpp"

#include <userver/clients/http/client.hpp>
#include <userver/clients/http/component.hpp>
#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/crypto/signers.hpp>
#include <userver/logging/log.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

namespace webpush {

namespace {

constexpr auto kDefaultRequestTimeout = std::chrono::seconds{10};

auto DoSend(
    userver::clients::http::Client& http_client,
    const Credentials& creds,
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

    // Generate VAPID auth header
    std::string auth_header;
    try {
        auth_header = vapid::GenerateAuthHeader(
            notification.subscription.endpoint,
            creds.subject,
            creds.private_key_pem,
            creds.public_key
        );
    } catch (const std::exception& e) {
        LOG_ERROR() << "VAPID token generation failed: " << e.what();
        return SendResult{.status_code = 0, .reason = e.what()};
    }

    std::shared_ptr<userver::clients::http::Response> response;
    try {
        response = http_client.CreateRequest()
                       .post(notification.subscription.endpoint, encrypted_body)
                       .headers({
                           {"Authorization", auth_header},
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

}  // namespace

struct Client::Impl {
    userver::components::HttpClient& http_client;
    Credentials credentials;
    std::chrono::milliseconds request_timeout;

    Impl(
        const userver::components::ComponentConfig& config,
        const userver::components::ComponentContext& context
    )
        : http_client(context.FindComponent<userver::components::HttpClient>())
        , credentials(Credentials::FromConfig(config))
        , request_timeout(config["request-timeout"].As<std::chrono::milliseconds>(kDefaultRequestTimeout)) {
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
        return DoSend(http_client.GetHttpClient(), credentials, notification, request_timeout);
    }

    auto Send(const Credentials& creds, const Notification& notification) const -> SendResult {
        return DoSend(http_client.GetHttpClient(), creds, notification, request_timeout);
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
        description: Contact URI (mailto: or https:)
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
