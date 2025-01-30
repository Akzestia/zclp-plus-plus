#include <unistd.h>

#include <cstdint>
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
    uint8_t len : 2;
    uint8_t* value;  // ((2^Len)*8)-2 bits
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
    uint64_t* upredictable_bits;
    uint8_t reset_token[16];
};

struct VersionNegotiation {
    uint8_t header_form : 1;
    uint8_t unused : 6;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
    std::vector<uint32_t> supported_versions;
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
    Frames::FrameVariant payload;  // Frames
};

struct ZeroRTT {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t packet_number : 3;
    Frames::FrameVariant payload;  // Frames
};

struct HandShake {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t packet_number : 3;
    Frames::FrameVariant payload;  // Frames
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
    Frames::FrameVariant payload;  // Frames
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
