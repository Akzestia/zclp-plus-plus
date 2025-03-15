#ifndef SERVER_ERRORS
#define SERVER_ERRORS

#include <cstdint>
#include <string>

enum SetupError : uint8_t {
    Success = 0,
    SocketCreationFailed = 1,
    SocketBindFailed = 2
};

inline bool operator!(SetupError error) {
    return error != Success;
}

inline std::string to_string(SetupError error) {
    switch (error) {
    case Success:
        return "Success";
    case SocketCreationFailed:
        return "SocketCreationFailed";
    case SocketBindFailed:
        return "SocketBindFailed";
    default:
        return "uknown";
    }
}

#endif  // SERVER_ERRORS
