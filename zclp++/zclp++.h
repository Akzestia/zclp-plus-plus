#ifndef ZCLP_PLUS_PLUS
#define ZCLP_PLUS_PLUS

#include <memory.h>
#include <unistd.h>

#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
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

struct EncodingResult {
    bool success;
    size_t len;

    bool operator!() { return success == false; }
    operator bool() const { return success; }
    operator uint64_t() const { return len; }
};

void printu8(const uint8_t* in, size_t len);

struct VariableLengthInteger {
  private:
    uint8_t len : 2;
    uint64_t value;

  public:
    VariableLengthInteger();

    explicit VariableLengthInteger(uint64_t val);

    size_t byte_size() const;

    VariableLengthInteger& operator=(uint64_t val);
    VariableLengthInteger& operator+=(uint64_t val);

    operator uint64_t() const { return value; }
    uint64_t operator()() const { return value; }
    uint8_t len_() const { return len; }
};

struct StatelessReset;
struct VersionNegotiation;
struct LongHeader;
struct ProtectedLongHeader;
struct Initial;
struct ZeroRTT;
struct HandShake;
struct Retry;
struct ShortHeader;

namespace zclp_encoding {
EncodingResult decode_vl_integer(uint8_t* in, VariableLengthInteger& out);
}

namespace Frames {

struct Padding {
    VariableLengthInteger type;  // 0
    size_t byte_size() const;
};

struct Ping {
    VariableLengthInteger type;  // 1
    size_t byte_size() const;
};

struct AckRange {
    VariableLengthInteger gap;    // 1
    VariableLengthInteger range;  // 1
    size_t byte_size() const;
};

struct EcnCount {
    VariableLengthInteger ect0;
    VariableLengthInteger ect1;
    VariableLengthInteger ecnce;
    size_t byte_size() const;
};

struct Ack {
    VariableLengthInteger type;  // 3 | 4
    VariableLengthInteger largest_ack_num;
    VariableLengthInteger delay;
    VariableLengthInteger range_count;
    std::vector<AckRange> ranges;
    std::optional<EcnCount> ecn_count;  // FT.Value == 3

    size_t byte_size() const;
};

struct ResetStream {
    VariableLengthInteger type;  // 4
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;
    VariableLengthInteger final_size;

    size_t byte_size() const;
};

struct StopSending {
    VariableLengthInteger type;  // 5;
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;

    size_t byte_size() const;
};

struct Crypto {
    VariableLengthInteger type;  // 6;
    VariableLengthInteger offset;
    VariableLengthInteger length;
    uint8_t* data;

    size_t byte_size() const;
};

struct NewToken {
    VariableLengthInteger type;  // 7;
    VariableLengthInteger length;
    uint8_t* token;

    size_t byte_size() const;
};

struct Stream {
    uint8_t unused : 5;  // 1
    uint8_t off : 1;
    uint8_t len : 1;
    uint8_t fin : 1;

    VariableLengthInteger stream_id;
    VariableLengthInteger length;
    uint8_t* stream_data;

    size_t byte_size() const;
};

struct MaxData {
    VariableLengthInteger type;  // 16
    VariableLengthInteger max_data;

    size_t byte_size() const;
};

struct MaxStreamData {
    VariableLengthInteger type;  // 17
    VariableLengthInteger stream_id;
    VariableLengthInteger max_stream_data;

    size_t byte_size() const;
};

struct MaxStreams {
    VariableLengthInteger type;  // 18 || 19
    VariableLengthInteger max_streams;

    size_t byte_size() const;
};

struct DataBlocked {
    VariableLengthInteger type;  // 20
    VariableLengthInteger data_limit;

    size_t byte_size() const;
};

struct StreamDataBlocked {
    VariableLengthInteger type;  // 21
    VariableLengthInteger stream_id;
    VariableLengthInteger stream_data_limit;

    size_t byte_size() const;
};

struct StreamsBlocked {
    VariableLengthInteger type;  // 22 || 23
    VariableLengthInteger stream_limit;

    size_t byte_size() const;
};

struct NewConnectionId {
    VariableLengthInteger type;  // 24
    VariableLengthInteger sequence_number;
    VariableLengthInteger retire_prior_to;
    uint32_t connection_id;
    uint8_t stateless_reset_token[16];

    size_t byte_size() const;
};

struct RetireConnectionId {
    VariableLengthInteger type;  // 25
    VariableLengthInteger sequence_number;

    size_t byte_size() const;
};

struct PathChallange {
    VariableLengthInteger type;  // 26
    uint64_t data;

    size_t byte_size() const;
};

struct PathResponse {
    VariableLengthInteger type;  // 27
    uint64_t data;

    size_t byte_size() const;
};

struct ConnectionClose {
    VariableLengthInteger type;  // 28 || 29
    VariableLengthInteger error;
    VariableLengthInteger frame_type;
    VariableLengthInteger phrase_len;
    uint8_t* phrase;

    size_t byte_size() const;
};

struct HandShakeDone {
    VariableLengthInteger type;  // 30

    size_t byte_size() const;
};

struct ClusterMask {
    VariableLengthInteger type;  // 31
    VariableLengthInteger mask_length;
    uint8_t* mask;
    size_t byte_size() const;
};

using FrameVariant =
    std::variant<Padding, Ping, Ack, ResetStream, StopSending, Crypto, NewToken,
                 Stream, MaxData, MaxStreamData, MaxStreams, DataBlocked,
                 StreamDataBlocked, StreamsBlocked, NewConnectionId,
                 RetireConnectionId, PathChallange, PathResponse,
                 ConnectionClose, HandShakeDone, ClusterMask>;

EncodingResult decode(uint8_t* in, Padding& out);
EncodingResult decode(uint8_t* in, Ping& out);
EncodingResult decode(uint8_t* in, AckRange& out);
EncodingResult decode(uint8_t* in, EcnCount& out);
EncodingResult decode(uint8_t* in, Ack& out);
EncodingResult decode(uint8_t* in, ResetStream& out);
EncodingResult decode(uint8_t* in, StopSending& out);
EncodingResult decode(uint8_t* in, Crypto& out);
EncodingResult decode(uint8_t* in, NewToken& out);
EncodingResult decode(uint8_t* in, Stream& out);
EncodingResult decode(uint8_t* in, MaxData& out);
EncodingResult decode(uint8_t* in, MaxStreamData& out);
EncodingResult decode(uint8_t* in, MaxStreams& out);
EncodingResult decode(uint8_t* in, DataBlocked& out);
EncodingResult decode(uint8_t* in, StreamDataBlocked& out);
EncodingResult decode(uint8_t* in, StreamsBlocked& out);
EncodingResult decode(uint8_t* in, NewConnectionId& out);
EncodingResult decode(uint8_t* in, RetireConnectionId& out);
EncodingResult decode(uint8_t* in, PathChallange& out);
EncodingResult decode(uint8_t* in, PathResponse& out);
EncodingResult decode(uint8_t* in, ConnectionClose& out);
EncodingResult decode(uint8_t* in, HandShakeDone& out);
EncodingResult decode(uint8_t* in, ClusterMask& out);
EncodingResult decode(uint8_t* in, Frames::FrameVariant& out);

EncodingResult encode(const Padding& in, uint8_t*& out);
EncodingResult encode(const Ping& in, uint8_t*& out);
EncodingResult encode(const AckRange& in, uint8_t*& out);
EncodingResult encode(const EcnCount& in, uint8_t*& out);
EncodingResult encode(const Ack& in, uint8_t*& out);
EncodingResult encode(const ResetStream& in, uint8_t*& out);
EncodingResult encode(const StopSending& in, uint8_t*& out);
EncodingResult encode(const Crypto& in, uint8_t*& out);
EncodingResult encode(const NewToken& in, uint8_t*& out);
EncodingResult encode(const Stream& in, uint8_t*& out);
EncodingResult encode(const MaxData& in, uint8_t*& out);
EncodingResult encode(const MaxStreamData& in, uint8_t*& out);
EncodingResult encode(const MaxStreams& in, uint8_t*& out);
EncodingResult encode(const DataBlocked& in, uint8_t*& out);
EncodingResult encode(const StreamDataBlocked& in, uint8_t*& out);
EncodingResult encode(const StreamsBlocked& in, uint8_t*& out);
EncodingResult encode(const NewConnectionId& in, uint8_t*& out);
EncodingResult encode(const RetireConnectionId& in, uint8_t*& out);
EncodingResult encode(const PathChallange& in, uint8_t*& out);
EncodingResult encode(const PathResponse& in, uint8_t*& out);
EncodingResult encode(const ConnectionClose& in, uint8_t*& out);
EncodingResult encode(const HandShakeDone& in, uint8_t*& out);
EncodingResult encode(const ClusterMask& in, uint8_t*& out);
EncodingResult encode(const Frames::FrameVariant& frame, uint8_t*& out);

size_t frame_size(const Frames::FrameVariant frame);

size_t frame_payload_size(std::vector<FrameVariant> payload);

enum FrameType : uint8_t {
    _Padding = 0,
    _Ping = 1,
    _Ack = 3,
    _ResetStream = 4,
    _StopSending = 5,
    _Crypto = 6,
    _NewToken = 7,
    _MaxData = 16,
    _MaxStreamData = 17,
    _MaxStreams = 19,
    _DataBlocked = 20,
    _StreamDataBlocked = 21,
    _StreamsBlocked = 23,
    _NewConnectionId = 24,
    _RetireConnectionId = 25,
    _PathChallange = 26,
    _PathResponse = 27,
    _ConnectionClose = 29,
    _HandShakeDone = 30,
    _ClusterMask = 31,
    _Stream = 99,
};

struct FrameResult {
    bool success;
    FrameType frame_type;
    FrameVariant frame;

    explicit operator bool() const { return success; }
    bool operator!() const { return success == false; }
};

FrameResult get_frame_type(uint8_t* in);
}  // namespace Frames

namespace Packets {

bool is_long_header(uint8_t* packet);

bool is_short_header(uint8_t* packet);

bool is_initial_packet(uint8_t* packet);

bool is_0rtt_packet(uint8_t* packet);

bool is_handshake_packet(uint8_t* packet);

bool is_retry_packet(uint8_t* packet);

enum PacketType {
    PACKET_UNKNOWN,
    PACKET_INITIAL,
    PACKET_0RTT,
    PACKET_HANDSHAKE,
    PACKET_RETRY,
    PACKET_SHORT_HEADER,
    PACKET_LONG_HEADER
};

bool operator!(const PacketType& type);

void printPacketType(enum PacketType type);

PacketType get_packet_type(uint8_t* packet);

struct StatelessReset {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;

    VariableLengthInteger unpredictable_bits;
    uint8_t reset_token[16];

    size_t byte_size() const;
};

struct VersionNegotiation {
    uint8_t header_form : 1;
    uint8_t unused : 6;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
    std::vector<uint32_t> supported_versions;

    size_t byte_size() const;
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

    size_t byte_size() const;

    /*
        HF = 1
        FB = 1
    */
    LongHeader() noexcept;
    LongHeader(PacketType PT) noexcept;
};

struct ProtectedLongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t protected_bits : 4;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;

    size_t byte_size() const;

    ProtectedLongHeader() noexcept;
    ProtectedLongHeader(PacketType PT) noexcept;
};

struct Initial {
    Packets::LongHeader header;

    // token length in bytes token_length()
    VariableLengthInteger token_length;
    uint8_t* token;

    // The length of the remainder of the packet in bytes length()
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const;
    void add_frame(const Frames::FrameVariant& frame, bool set_len = true);

    Initial() noexcept;
};

struct ZeroRTT {
    LongHeader header;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const;
};

struct HandShake {
    LongHeader header;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const;
};

struct Retry {
    LongHeader header;
    uint8_t* token;
    uint8_t integrity_tag[16];

    size_t byte_size() const;
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

    size_t byte_size() const;

    /*
        HF = 0
        FB = 1
    */
    ShortHeader() noexcept;
};

}  // namespace Packets

namespace Structs {

/*
    ACS

    Authentication and cluster setup

    ///\\\///\\\///\\\///\\\///\\\///\\\///\\\///\\\

    CR

    Client request

    ///\\\///\\\///\\\///\\\///\\\///\\\///\\\///\\\

    P2P

    p2p connection

    ///\\\///\\\///\\\///\\\///\\\///\\\///\\\///\\\
*/

enum C_Type : uint8_t {
    ACS = 0,
    CR = 1,
    P2P = 2,
};

struct Connection {
    uint32_t id;
    C_Type type;
    uint32_t params;
    std::atomic<bool> alive;

    /*
        Destination Cluster Mask

        Will be sent as a separate frame,
        which will contain all necessary information
        about receiver's cluster mask.

        ///\\\///\\\///\\\///\\\///\\\///\\\///\\\///\\\

        Cluster Mask

        Assigned dynamically to users when they connect to a cluster.
        Formed as followed: cluster_name|^|user_name.

        ///\\\///\\\///\\\///\\\///\\\///\\\///\\\///\\\

        Cluster and User Registry

        Both clusters and users have single registry.
    */
    std::optional<std::string> destination_cluster_mask;
};
}  // namespace Structs

#endif  // ZCLP_PLUS_PLUS
