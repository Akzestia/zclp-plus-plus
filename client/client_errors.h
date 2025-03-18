#ifndef CLIENT_ERRORS
#define CLIENT_ERRORS

#include <cstdint>
#include <variant>

/*
    The names of some errors are Identical
    to the ones defined in other files like server/server_errors.hpp etc.
    I just want `em being separated for the future ease of use and modifications

    Use enum class to avaoid redefinition errors in the same scope
*/

namespace client_errors {
enum class SetupError : uint8_t {
    SocketCreationFailed = 1,
    SocketBindFailed = 2
};

enum class ConnectionError : uint8_t {
    FailedToEstablish = 1,
    CanceledByHost = 2,
};

enum class EncodingError : uint8_t {
    EncodingFailed = 1,
    DecodingFailed = 2,
};

enum class StreamError : uint8_t {
    StreamClosed = 1,
    StreamInterupted = 2,
    StreamDataLoss = 3
};

enum class DNS_Error : uint8_t { AddressParsingFailed = 1 };

enum class SocketError : uint8_t { FailedToSend = 1 };

using ClientError = std::variant<SetupError, ConnectionError, EncodingError,
                                 StreamError, DNS_Error, SocketError>;

}  // namespace client_errors

#endif  // CLIENT_ERRORS
