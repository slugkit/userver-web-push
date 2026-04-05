#pragma once

#include <string>

#include <userver/components/component_config.hpp>

namespace webpush {

struct Credentials {
    std::string private_key_pem;
    std::string public_key;       // base64url-encoded uncompressed P-256 public key
    std::string subject;          // contact URI, e.g. "mailto:admin@example.com"

    static auto FromConfig(const userver::components::ComponentConfig& config) -> Credentials;
};

}  // namespace webpush
