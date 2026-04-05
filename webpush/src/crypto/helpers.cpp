#include "helpers.hpp"

#include <openssl/err.h>

USERVER_NAMESPACE_BEGIN

namespace crypto::impl {

std::string FormatSslError(std::string message) {
    bool first = true;
    unsigned long ssl_error = 0;

    while ((ssl_error = ERR_get_error()) != 0) {
        if (first) {
            message += ": ";
            first = false;
        } else {
            message += "; ";
        }

        const char* reason = ERR_reason_error_string(ssl_error);
        if (reason) {
            message += reason;
        } else {
            message += "unknown error";
        }
    }
    return message;
}

}  // namespace crypto::impl

USERVER_NAMESPACE_END
