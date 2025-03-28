#ifndef ZCLP_RPC_ERRORS_H
#define ZCLP_RPC_ERRORS_H
#include <cstdint>
#include <variant>

namespace zclp_rpc_errors {

enum class CallBackError : uint8_t {
    NotDefined = 1,
};

enum class SchemeError : uint8_t {

};

enum class RequestError : uint8_t {

};

enum class ResponseError : uint8_t {

};

using RpcError =
    std::variant<CallBackError, SchemeError, RequestError, ResponseError>;

}  // namespace zclp_rpc_errors

#endif  // ZCLP_RPC_ERRORS_H
