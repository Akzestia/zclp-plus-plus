#ifndef ZCLP_PLUS_PLUS
#define ZCLP_PLUS_PLUS

#include <memory.h>
#include <unistd.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <variant>
#include <vector>

/*
    https://www.ietf.org/archive/id/draft-mcquistin-quic-augmented-diagrams-05.html

    ///-\\\///-\\\///-\\\           ///-\\\///-\\\///-\\\
    \\\-///\\\-///\\\-///           \\\-///\\\-///\\\-///

    ///-\\\///-\\\///-\\\           ///-\\\///-\\\///-\\\
    \\\-///\\\-///\\\-///           \\\-///\\\-///\\\-///

    Bits	      Binary Mask	     Hex Mask	   Decimal Mask
    1-bit	      00000001	         0x01	       1
    2-bit	      00000011	         0x03	       3
    3-bit	      00000111	         0x07	       7
    4-bit	      00001111	         0x0F	       15
    5-bit	      00011111	         0x1F	       31
    6-bit	      00111111	         0x3F	       63
    7-bit	      01111111	         0x7F	       127
    8-bit	      11111111	         0xFF	       255
*/

template<class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};

template<class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

struct VariableLengthInteger {
  private:
    uint8_t len : 2;
    uint64_t value;

  public:
    VariableLengthInteger() : len(0), value(0) {}

    explicit VariableLengthInteger(uint64_t val) { *this = val; }

    size_t byte_size() const { return pow(2, len); }

    VariableLengthInteger& operator=(uint64_t val) {
        uint8_t required_len;
        if (val <= 0x3F)
            required_len = 0;  // 6 bits (1 byte) 63
        else if (val <= 0x3FFF)
            required_len = 1;  // 14 bits (2 bytes) 16,383
        else if (val <= 0x3FFFFFFF)
            required_len = 2;  // 30 bits (4 bytes) 1,073,741,823
        else
            required_len = 3;  // 62 bits (8 bytes) 4,611,686,018,427,387,903

        uint64_t max_val = (1ULL << ((1 << required_len) * 8 - 2)) - 1;
        if (val > max_val) {
            throw "Way too big value";
        }
        len = required_len;
        value = val;
        return *this;
    }

    operator uint64_t() const { return value; }
    uint64_t operator()() const { return value; }
    uint8_t len_() const { return len; }
};

namespace Frames {
struct Padding {
    VariableLengthInteger type;  // 0
    size_t byte_size() const { return type.byte_size(); }
};

struct Ping {
    VariableLengthInteger type;  // 1
    size_t byte_size() const { return type.byte_size(); }
};

struct AckRange {
    VariableLengthInteger gap;    // 1
    VariableLengthInteger range;  // 1
    size_t byte_size() const { return gap.byte_size() + range.byte_size(); }
};

struct EcnCount {
    VariableLengthInteger ect0;
    VariableLengthInteger ect1;
    VariableLengthInteger ecnce;
    size_t byte_size() const {
        return ect0.byte_size() + ect1.byte_size() + ecnce.byte_size();
    }
};

struct Ack {
    VariableLengthInteger type;  // 3 | 4
    VariableLengthInteger largest_ack_num;
    VariableLengthInteger delay;
    VariableLengthInteger range_count;
    std::vector<AckRange> ranges;
    std::optional<EcnCount> ecn_count;  // FT.Value == 3

    size_t byte_size() const {
        size_t ranges_size = 0;
        for (auto range : ranges)
            ranges_size += range.byte_size();

        if (ecn_count.has_value())
            ranges_size += ecn_count.value().byte_size();

        return type.byte_size() + largest_ack_num.byte_size()
            + delay.byte_size() + range_count.byte_size() + ranges_size;
    }
};

struct ResetStream {
    VariableLengthInteger type;  // 4
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;
    VariableLengthInteger final_size;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size() + error_code.byte_size()
            + final_size.byte_size();
    }
};

struct StopSending {
    VariableLengthInteger type;  // 5;
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size()
            + error_code.byte_size();
    }
};

struct Crypto {
    VariableLengthInteger type;  // 6;
    VariableLengthInteger offset;
    VariableLengthInteger length;
    uint8_t* data;

    size_t byte_size() const {
        return type.byte_size() + offset.byte_size() + length.byte_size()
            + length();
    }
};

struct NewToken {
    VariableLengthInteger type;  // 7;
    VariableLengthInteger length;
    uint8_t* token;

    size_t byte_size() const {
        return type.byte_size() + length.byte_size() + length();
    }
};

struct Stream {
    uint8_t unused : 5;  // 1
    uint8_t off : 1;
    uint8_t len : 1;
    uint8_t fin : 1;

    VariableLengthInteger stream_id;
    VariableLengthInteger length;
    uint8_t* stream_data;

    size_t byte_size() const {
        return 1 + stream_id.byte_size() + length.byte_size() + length();
    }
};

struct MaxData {
    VariableLengthInteger type;  // 16
    VariableLengthInteger max_data;

    size_t byte_size() const { return type.byte_size() + max_data.byte_size(); }
};

struct MaxStreamData {
    VariableLengthInteger type;  // 17
    VariableLengthInteger stream_id;
    VariableLengthInteger max_stream_data;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size()
            + max_stream_data.byte_size();
    }
};

struct MaxStreams {
    VariableLengthInteger type;  // 18 || 19
    VariableLengthInteger max_streams;

    size_t byte_size() const {
        return type.byte_size() + max_streams.byte_size();
    }
};

struct DataBlocked {
    VariableLengthInteger type;  // 20
    VariableLengthInteger data_limit;

    size_t byte_size() const {
        return type.byte_size() + data_limit.byte_size();
    }
};

struct StreamDataBlocked {
    VariableLengthInteger type;  // 21
    VariableLengthInteger stream_id;
    VariableLengthInteger stream_data_limit;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size()
            + stream_data_limit.byte_size();
    }
};

struct StreamsBlocked {
    VariableLengthInteger type;  // 22 || 23
    VariableLengthInteger stream_limit;

    size_t byte_size() const {
        return type.byte_size() + stream_limit.byte_size();
    }
};

struct NewConnectionId {
    VariableLengthInteger type;  // 24
    VariableLengthInteger sequence_number;
    VariableLengthInteger retire_prior_to;
    uint32_t connection_id;
    uint8_t stateless_reset_token[16];

    size_t byte_size() const {
        return type.byte_size() + sequence_number.byte_size()
            + retire_prior_to.byte_size() + 4 + 16;
    }
};

struct RetireConnectionId {
    VariableLengthInteger type;  // 25
    VariableLengthInteger sequence_number;

    size_t byte_size() const {
        return type.byte_size() + sequence_number.byte_size();
    }
};

struct PathChallange {
    VariableLengthInteger type;  // 26
    uint64_t data;

    size_t byte_size() const { return type.byte_size() + 8; }
};

struct PathResponse {
    VariableLengthInteger type;  // 27
    uint64_t data;

    size_t byte_size() const { return type.byte_size() + 8; }
};

struct ConnectionClose {
    VariableLengthInteger type;  // 28 || 29
    VariableLengthInteger error;
    VariableLengthInteger frame_type;
    VariableLengthInteger phrase_len;
    uint8_t* phrase;

    size_t byte_size() const {
        return type.byte_size() + error.byte_size() + frame_type.byte_size()
            + phrase_len.byte_size();
    }
};

struct HandShakeDone {
    VariableLengthInteger type;  // 30

    size_t byte_size() const { return type.byte_size(); }
};

using FrameVariant =
    std::variant<Padding, Ping, Ack, ResetStream, StopSending, Crypto, NewToken,
                 Stream, MaxData, MaxStreamData, MaxStreams, DataBlocked,
                 StreamDataBlocked, StreamsBlocked, NewConnectionId,
                 RetireConnectionId, PathChallange, PathResponse,
                 ConnectionClose, HandShakeDone>;

inline size_t frame_size(const Frames::FrameVariant frame) {
    return std::visit(
        overloaded{
            [](const Frames::Padding& f) -> size_t { return f.byte_size(); },
            [](const Frames::Ping& f) -> size_t { return f.byte_size(); },
            [](const Frames::Ack& f) -> size_t { return f.byte_size(); },
            [](const Frames::ResetStream& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::StopSending& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::Crypto& f) -> size_t { return f.byte_size(); },
            [](const Frames::NewToken& f) -> size_t { return f.byte_size(); },
            [](const Frames::Stream& f) -> size_t { return f.byte_size(); },
            [](const Frames::MaxData& f) -> size_t { return f.byte_size(); },
            [](const Frames::MaxStreamData& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::MaxStreams& f) -> size_t { return f.byte_size(); },
            [](const Frames::DataBlocked& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::StreamDataBlocked& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::StreamsBlocked& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::NewConnectionId& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::RetireConnectionId& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::PathChallange& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::PathResponse& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::ConnectionClose& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::HandShakeDone& f) -> size_t {
                return f.byte_size();
            }},
        frame);
}

inline size_t frame_payload_size(std::vector<FrameVariant> payload) {
    size_t size = 0;
    for (auto x : payload)
        size += frame_size(x);
    return size;
}
}  // namespace Frames

namespace Packets {

struct StatelessReset {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;

    VariableLengthInteger unpredictable_bits;
    uint8_t reset_token[16];

    size_t byte_size() const {
        /*
            16 bytes token
            1 byte HF && FBs
            N bytes unpredictable_bits.size()
        */
        return 16 + 1 + unpredictable_bits.byte_size();
    }
};

struct VersionNegotiation {
    uint8_t header_form : 1;
    uint8_t unused : 6;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
    std::vector<uint32_t> supported_versions;

    size_t byte_size() const {
        /*
            1 byte HF && unused
            12 bytes version_id && destination_connection_id &&
            source_connection_id
            4 * N bytes supported_versions
        */
        return 13 + 4 * supported_versions.size();
    }
};

struct LongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t reserved_bits : 2;
    uint8_t packet_number_length : 2;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;

    size_t byte_size() const {
        /*
            1 byte - ..version_id
            12 bytes version_id + destination_connection_id +
           source_connection_id
        */
        return 13;
    }
};

struct ProtectedLongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t protected_bits : 4;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;

    size_t byte_size() const {
        /*
            1 byte - ..version_id
            12 bytes version_id + destination_connection_id +
           source_connection_id
        */
        return 13;
    }
};

struct Initial {
    LongHeader header;

    // token length in bytes token_length()
    VariableLengthInteger token_length;
    uint8_t* token;

    // The length of the remainder of the packet in bytes length()
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const {
        return header.byte_size() + token_length() + length();
    }
};

struct ZeroRTT {
    LongHeader header;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const { return header.byte_size() + length(); }
};

struct HandShake {
    LongHeader header;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const { return header.byte_size() + length(); }
};

struct Retry {
    LongHeader header;
    uint8_t* token;
    uint8_t integrity_tag[16];

    size_t byte_size() const {
        /*
            token len external
            ||
            Retry packet size - header - integrity_tag size
        */
        return header.byte_size() + 16;
    }
};

struct ShortHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t spin_bit : 1;
    uint8_t reserved_bits : 2;
    uint8_t key_phase : 1;
    uint8_t packet_number_length : 2;
    uint32_t destination_connection;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const {
        /*

        */
        return 2 + 4 + Frames::frame_payload_size(payload);
    }
};

}  // namespace Packets

namespace Protection {
/*
func remove_protection(from: Protected Packet) -> Unprotected Packet:
   remove header protection from protected_packet
   remove packet protection from protected_packet
   construct appropriate packet type
   return Unprotected Packet

   func apply_protection(to: Unprotected Packet)
                   -> Protected Packet:
      apply packet protection to payload
      apply header protection to first_byte and packet_number
      construct appropriate Protected Packet based on first_byte
      return Protected Packet
*/
}
#endif  // ZCLP_PLUS_PLUS
