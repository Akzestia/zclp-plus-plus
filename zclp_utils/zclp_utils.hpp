#include <cstdint>
#include "../zclp++.hpp"

namespace zclp_parsing {
template<typename T>
struct ParserResult {
    bool success;
    size_t bytes_read;
    T value;
};

inline bool is_long_header(uint8_t first_byte) {
    return (first_byte & 0x80) == 1 && ((first_byte & 0x40) == 1);
}

//short header | stateless reset
inline bool is_short_header(uint8_t first_byte) {
    return (first_byte & 0x80) == 0 && ((first_byte & 0x40) == 1);
}

inline ParserResult<uint64_t> parse_variable_length_integer(const uint8_t* data,
                                                            ssize_t len) {
    if (len < 1) {
        return {false, 0, 0};
    }

    uint8_t first_byte = data[0];
    uint8_t type = first_byte >> 6;
    size_t length = 1 << type;

    if (len < length) {
        return {false, 0, 0};
    }

    uint64_t value = 0;
    for (size_t i = 0; i < length; i++) {
        value = (value << 8) | data[i];
    }
    value &= (1ULL << ((length * 8) - 2)) - 1;

    return {true, length, value};
}

inline ParserResult<Packets::ShortHeader> parse_short_header(const uint8_t* data, ssize_t len);
inline ParserResult<Packets::LongHeader> parse_long_header(const uint8_t* data, ssize_t len);

}  // namespace zclp_parsing

namespace zclp_encoding {
struct EncodingResult {
    bool success;
    size_t bytes_written;
};

inline EncodingResult encode_variable_length_integer(uint64_t value,
                                                     uint8_t* out,
                                                     size_t max_len) {
    if (value < (1ULL << 6)) {
        if (max_len < 1)
            return {false, 0};
        out[0] = static_cast<uint8_t>(value);
        return {true, 1};
    } else if (value < (1ULL << 14)) {
        if (max_len < 2)
            return {false, 0};
        uint16_t encoded = static_cast<uint16_t>(value | 0x4000);
        out[0] = encoded >> 8;
        out[1] = encoded & 0xFF;
        return {true, 2};
    } else if (value < (1ULL << 30)) {
        if (max_len < 4)
            return {false, 0};
        uint32_t encoded = static_cast<uint32_t>(value | 0x80000000);
        for (int i = 0; i < 4; i++) {
            out[i] = (encoded >> (24 - i * 8)) & 0xFF;
        }
        return {true, 4};
    } else if (value < (1ULL << 62)) {
        if (max_len < 8)
            return {false, 0};
        uint64_t encoded = value | 0xC000000000000000;
        for (int i = 0; i < 8; i++) {
            out[i] = (encoded >> (56 - i * 8)) & 0xFF;
        }
        return {true, 8};
    }
    return {false, 0};
}
}  // namespace zclp_encoding
