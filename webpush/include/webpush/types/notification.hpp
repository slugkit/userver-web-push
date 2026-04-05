#pragma once

#include <cstdint>
#include <string>

#include <webpush/types/subscription.hpp>

namespace webpush {

struct Notification {
    Subscription subscription;
    std::string payload;
    std::int32_t ttl = 3600;
};

}  // namespace webpush
