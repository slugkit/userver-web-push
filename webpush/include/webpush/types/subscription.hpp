#pragma once

#include <string>

namespace webpush {

struct Subscription {
    std::string endpoint;
    std::string p256dh;     // base64url
    std::string auth;       // base64url
};

}  // namespace webpush
