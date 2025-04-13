#ifndef ZCLP_GENERICS_H
#define ZCLP_GENERICS_H

#include <variant>

#include "../client/client_errors.h"
#include "../server/server_errors.h"

namespace zclp_generics {

enum class GenericResults : uint8_t {
    Success = 0,
    Failure = 1,
    Undefined = 2,
};

using ZclpError = std::variant<client_errors::ClientError,
                               server_errors::ServerError, GenericResults>;

struct ZclpResult {
    bool success = false;
    ZclpError error;

    bool operator!();
    operator int() const { return success; };

    [[nodiscard]] static ZclpResult Success() noexcept;
    [[nodiscard]] static ZclpResult Failure(ZclpError error) noexcept;
};

}  // namespace zclp_generics

#endif  // ZCLP_GENERICS_H
