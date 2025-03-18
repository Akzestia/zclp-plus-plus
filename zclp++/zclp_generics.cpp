#include "zclp_generics.h"

namespace zclp_generics {
ZclpResult ZclpResult::Success() noexcept {
    return {true, GenericResults::Success};
}

ZclpResult ZclpResult::Failure(ZclpError error) noexcept {
    return {false, error};
}

bool ZclpResult::operator!() {
    return !success;
}

}  // namespace zclp_generics
