#include <webpush/handlers/debug_send.hpp>

#include <webpush/components/client.hpp>

#include <userver/components/component_config.hpp>
#include <userver/components/component_context.hpp>
#include <userver/formats/json/serialize.hpp>
#include <userver/formats/json/value_builder.hpp>
#include <userver/logging/log.hpp>
#include <userver/server/handlers/exceptions.hpp>
#include <userver/yaml_config/merge_schemas.hpp>

namespace webpush::handlers {

namespace uhandlers = userver::server::handlers;
namespace json = userver::formats::json;

struct DebugSend::Impl {
    const Client& webpush_client;

    Impl(const userver::components::ComponentConfig& config, const userver::components::ComponentContext& context)
        : webpush_client(
              context.FindComponent<Client>(config["webpush-client"].As<std::string>("webpush-client"))
          ) {}
};

DebugSend::DebugSend(
    const userver::components::ComponentConfig& config,
    const userver::components::ComponentContext& context
)
    : BaseType{config, context}
    , impl_{config, context} {}

DebugSend::~DebugSend() = default;

auto DebugSend::HandleRequestJsonThrow(
    [[maybe_unused]] const userver::server::http::HttpRequest& request,
    const json::Value& request_json,
    [[maybe_unused]] userver::server::request::RequestContext& context
) const -> json::Value {
    if (!request_json.HasMember("subscription")) {
        throw uhandlers::ClientError(
            uhandlers::InternalMessage{"Missing required field: subscription"},
            uhandlers::ExternalBody{R"({"error":"missing field: subscription"})"}
        );
    }
    if (!request_json.HasMember("payload")) {
        throw uhandlers::ClientError(
            uhandlers::InternalMessage{"Missing required field: payload"},
            uhandlers::ExternalBody{R"({"error":"missing field: payload"})"}
        );
    }

    auto sub_json = request_json["subscription"];
    Subscription subscription;
    subscription.endpoint = sub_json["endpoint"].As<std::string>();
    subscription.p256dh = sub_json["keys"]["p256dh"].As<std::string>();
    subscription.auth = sub_json["keys"]["auth"].As<std::string>();

    Notification notification;
    notification.subscription = std::move(subscription);
    notification.payload = json::ToString(request_json["payload"]);

    if (request_json.HasMember("ttl")) {
        notification.ttl = request_json["ttl"].As<std::int32_t>();
    }

    LOG_INFO() << "Debug Web Push send to endpoint=" << notification.subscription.endpoint;

    auto result = impl_->webpush_client.Send(notification);

    json::ValueBuilder response;
    response["status_code"] = result.status_code;
    response["reason"] = result.reason;

    if (result.status_code != 201 && result.status_code != 200 && result.status_code != 0) {
        auto& http_response = request.GetHttpResponse();
        http_response.SetStatus(static_cast<userver::server::http::HttpStatus>(result.status_code));
    } else if (result.status_code == 0) {
        auto& http_response = request.GetHttpResponse();
        http_response.SetStatus(userver::server::http::HttpStatus::kBadGateway);
    }

    return response.ExtractValue();
}

auto DebugSend::GetStaticConfigSchema() -> userver::yaml_config::Schema {
    return userver::yaml_config::MergeSchemas<BaseType>(R"(
type: object
description: Debug handler for sending Web Push notifications
additionalProperties: false
properties:
    webpush-client:
        type: string
        description: Component name for the Web Push client
        defaultDescription: webpush-client
    )");
}

}  // namespace webpush::handlers
