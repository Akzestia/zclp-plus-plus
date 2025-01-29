#include <cstdint>
#include <vector>

/*
    https://www.ietf.org/archive/id/draft-mcquistin-quic-augmented-diagrams-05.html

    ///-\\\///-\\\///-\\\           ///-\\\///-\\\///-\\\
    \\\-///\\\-///\\\-///           \\\-///\\\-///\\\-///

    ///-\\\///-\\\///-\\\           ///-\\\///-\\\///-\\\
    \\\-///\\\-///\\\-///           \\\-///\\\-///\\\-///
*/
namespace Packets {

struct VariableLengthInteger {
    uint8_t len : 2;
    uint8_t* value;
} __attribute__((packed));

struct StatelessReset {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint64_t* upredictable_bits;
    uint8_t reset_token[16];
} __attribute__((packed));

struct VersionNegotiation {
    uint8_t header_form : 1;
    uint8_t unused : 6;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
    std::vector<uint32_t> supported_versions;
} __attribute__((packed));

struct LongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t reserved_bits : 2;
    uint8_t pakcet_number_length : 2;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
} __attribute__((packed));

struct ProtectedLongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t protected_bits : 4;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
} __attribute__((packed));

struct Initial {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t* token;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    void* payload;  // Frames
} __attribute__((packed));

struct ZeroRTT {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t packet_number : 3;
    void* payload;  // Frames
} __attribute__((packed));

struct HandShake {
    LongHeader header;
    VariableLengthInteger token_length;
    uint8_t packet_number : 3;
    void* payload;  // Frames
} __attribute__((packed));

struct Retry {
    LongHeader header;
    uint8_t* token;
    uint8_t integrity_tag[16];
} __attribute__((packed));

struct ShortHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t spin_bit : 1;
    uint8_t reserved_bits : 2;
    uint8_t key_phase : 1;
    uint8_t packet_number_length : 2;
    uint32_t destination_connection;
    uint8_t packet_number : 3;
} __attribute__((packed));

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
