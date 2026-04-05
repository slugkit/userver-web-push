#include <webpush/types/credentials.hpp>

namespace webpush {

auto Credentials::FromConfig(const userver::components::ComponentConfig& config) -> Credentials {
    return Credentials{
        .private_key_pem = config["private-key-pem"].As<std::string>(),
        .public_key = config["public-key"].As<std::string>(),
        .subject = config["subject"].As<std::string>(),
    };
}

}  // namespace webpush
