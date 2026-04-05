#pragma once

#include <cstdint>
#include <string>

namespace webpush {

struct SendResult {
    /// HTTP status (201 = success, 400-503 = error, 0 = transport error).
    std::int32_t status_code;
    std::string reason;
};

}  // namespace webpush
