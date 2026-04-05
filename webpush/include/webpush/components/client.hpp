#pragma once

#include <webpush/types/credentials.hpp>
#include <webpush/types/notification.hpp>
#include <webpush/types/result.hpp>

#include <userver/components/component_base.hpp>
#include <userver/utils/fast_pimpl.hpp>
#include <userver/yaml_config/schema.hpp>

namespace webpush {

class Client final : public userver::components::ComponentBase {
public:
    static constexpr std::string_view kName = "webpush-client";

    Client(
        const userver::components::ComponentConfig& config,
        const userver::components::ComponentContext& context
    );
    ~Client();

    static auto GetStaticConfigSchema() -> userver::yaml_config::Schema;

    [[nodiscard]] auto Send(const Notification& notification) const -> SendResult;

    [[nodiscard]] auto Send(
        const Credentials& credentials,
        const Notification& notification
    ) const -> SendResult;

private:
    constexpr static auto kImplSize = 112UL;
    constexpr static auto kImplAlign = 8UL;
    struct Impl;
    userver::utils::FastPimpl<Impl, kImplSize, kImplAlign> impl_;
};

}  // namespace webpush
