#include "zclp_request.h"

#include "zclp_generics.h"
#include "zclp_rpc_errors.h"

namespace zclp_request {

Buffer::Buffer() noexcept : data(nullptr), size(0) {
}

Buffer::Buffer(uint8_t* data, size_t size) noexcept : data(data), size(size) {
}

ZclpRequest::ZclpRequest(uint32_t stream_id, uint8_t*& request,
                         size_t request_size) noexcept
    : m_stream_id(stream_id), m_request(request, request_size) {
}

bool ZclpRequest::operator!() const {
    return m_success;
}

bool ZclpRequest::is_processing() const {
    return m_is_processing.load();
}

ZclpResult ZclpRequest::emit() {
    if (!response_callback)
        return ZclpResult::Failure(zclp_rpc_errors::CallBackError::NotDefined);

    return ZclpResult::Success();
}

}  // namespace zclp_request
