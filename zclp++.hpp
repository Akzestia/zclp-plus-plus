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
*/

struct VariableLengthInteger {
  private:
    uint8_t len : 2;
    uint64_t value;

  public:
    VariableLengthInteger() : len(0), value(0) {}

    explicit VariableLengthInteger(uint64_t val) { *this = val; }

    size_t size() const { return pow(2, len); }

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
};

struct Ping {
    VariableLengthInteger type;  // 1
};

struct AckRange {
    VariableLengthInteger gap;    // 1
    VariableLengthInteger range;  // 1
};

struct EcnCount {
    VariableLengthInteger ect0;
    VariableLengthInteger ect1;
    VariableLengthInteger ecnce;
};

struct Ack {
    VariableLengthInteger type;  // 3 | 4
    VariableLengthInteger largest_ack_num;
    VariableLengthInteger delay;
    VariableLengthInteger range_count;
    std::vector<AckRange> ranges;
    std::optional<EcnCount> ecn_count;  // FT.Value == 3
};

struct ResetStream {
    VariableLengthInteger type;  // 4
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;
    VariableLengthInteger final_size;
};

struct StopSending {
    VariableLengthInteger type;  // 5;
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;
};

struct Crypto {
    VariableLengthInteger type;  // 6;
    VariableLengthInteger offset;
    VariableLengthInteger length;
    uint8_t* data;
};

struct NewToken {
    VariableLengthInteger type;  // 7;
    VariableLengthInteger length;
    uint8_t* token;
};

struct Stream {
    uint8_t unused : 5;  // 1
    uint8_t off : 1;
    uint8_t len : 1;
    uint8_t fin : 1;

    VariableLengthInteger stream_id;
    VariableLengthInteger length;
    uint8_t* stream_data;
};

struct MaxData {
    VariableLengthInteger type;  // 16
    VariableLengthInteger max_data;
};

struct MaxStreamData {
    VariableLengthInteger type;  // 17
    VariableLengthInteger stream_id;
    VariableLengthInteger max_stream_data;
};

struct MaxStreams {
    VariableLengthInteger type;  // 18 || 19
    VariableLengthInteger max_streams;
};

struct DataBlocked {
    VariableLengthInteger type;  // 20
    VariableLengthInteger data_limit;
};

struct StreamDataBlocked {
    VariableLengthInteger type;  // 21
    VariableLengthInteger stream_id;
    VariableLengthInteger stream_data_limit;
};

struct StreamsBlocked {
    VariableLengthInteger type;  // 22 || 23
    VariableLengthInteger stream_limit;
};

struct NewConnectionId {
    VariableLengthInteger type;  // 24
    VariableLengthInteger sequence_number;
    VariableLengthInteger retire_prior_to;
    uint8_t length;  // 1 >= 20? => FRAME_ENCODING_ERROR
    uint8_t connection_id;
    uint8_t stateless_reset_token[16];
};

struct RetireConnectionId {
    VariableLengthInteger type;  // 25
    VariableLengthInteger sequence_number;
};

struct PathChallange {
    VariableLengthInteger type;  // 26
    uint64_t data;
};

struct PathResponse {
    VariableLengthInteger type;  // 27
    uint64_t data;
};

struct ConnectionClose {
    VariableLengthInteger type;  // 28 || 29
    VariableLengthInteger error;
    VariableLengthInteger frame_type;
    VariableLengthInteger phrase_len;
    uint8_t phrase;
};

struct HandShakeDone {
    VariableLengthInteger type;  // 30
};

using FrameVariant =
    std::variant<Padding, Ping, Ack, ResetStream, StopSending, Crypto, NewToken,
                 Stream, MaxData, MaxStreamData, MaxStreams, DataBlocked,
                 StreamDataBlocked, StreamsBlocked, NewConnectionId,
                 RetireConnectionId, PathChallange, PathResponse,
                 ConnectionClose, HandShakeDone>;
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
        return 16 + 1 + unpredictable_bits.size();
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
        return 15 + 4 * supported_versions.size();
    }
};

struct LongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t reserved_bits : 2;
    uint8_t pakcet_number_length : 2;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
};

struct ProtectedLongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t protected_bits : 4;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
};

struct Initial {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t* token;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames
};

struct ZeroRTT {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames
};

struct HandShake {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames
};

struct Retry {
    LongHeader header;
    uint8_t* token;
    uint8_t integrity_tag[16];
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
