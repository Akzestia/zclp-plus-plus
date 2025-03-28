#ifndef ZCLP_REQUEST_H
#define ZCLP_REQUEST_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "zclp_generics.h"
namespace zclp_request {

enum class ZclpRequestError : uint8_t {
    ConnectionFailed = 1,
    InvalidRpc = 2,
    NotAuthorized = 3,
    RateLimit = 4,
    TimedOut = 5,
    NegotiationFailure = 6,
    StreamCanceled = 7,
};

/*
    Buffer struct
*/
struct Buffer {
    uint8_t* data;
    size_t size;

    [[nodiscard]] Buffer() noexcept;
    [[nodiscard]] Buffer(uint8_t* data, size_t size) noexcept;
};

/*
    ZclpRequest doesn't provide encryption!!!

    You must only use it, with already encrypted data;

    func get_some_data(data, size, stream_id){
        encrypt_data(data, size);
        ZclpRequest request(stream_id, data, size);

        request.setting = ...;
        request.setting = ...;
        request.setting = ...;
        request.setting = ...;
        request.setting = ...;

        if(!request.emit())
            handle error
    }


    ZclpRequest provides response_callback() for handling logic, after it
    finishes.
*/

using namespace zclp_generics;

struct ZclpRequest {
    [[nodiscard]] ZclpRequest(uint32_t stream_id, uint8_t*& request,
                              size_t request_size) noexcept;
    ~ZclpRequest() noexcept;

    bool operator!() const;
    bool is_processing() const;

    ZclpResult emit();

    std::function<void()> response_callback = nullptr;

  private:
    bool m_success;
    ZclpRequestError m_error;

    uint32_t m_stream_id;
    std::atomic<bool> m_is_processing;
    /*
        Request includes encrypted data sent by client.
        Response includes encrypted data received from the server/client;
    */
    Buffer m_request;
    Buffer m_response;
};

};  // namespace zclp_request

#endif  // ZCLP_REQUEST_H
