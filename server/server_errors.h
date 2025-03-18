#ifndef SERVER_ERRORS
#define SERVER_ERRORS

#include <cstdint>
#include <string>
#include <variant>

/*
    The names of some errors are Identical
    to the ones defined in other files like client/client_errors.hpp etc.
    I just want `em being separated for the future ease of use and modifications

    Use enum class to avaoid redefinition errors in the same scope
*/

namespace server_errors {

enum class SetupError : uint8_t {
    SocketCreationFailed = 0,
    SocketBindFailed = 1
};

using ServerError = std::variant<SetupError>;

}  // namespace server_errors
#endif  // SERVER_ERRORS
