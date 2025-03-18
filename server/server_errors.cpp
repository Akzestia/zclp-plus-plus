#include "server_errors.h"

namespace server_errors {
inline std::string to_string(SetupError error) {
    switch (error) {
    case SetupError::SocketCreationFailed:
        return "SocketCreationFailed";
    case SetupError::SocketBindFailed:
        return "SocketBindFailed";
    default:
        return "uknown";
    }
}
}  // namespace server_errors
