#ifndef ZCLP_UTILS
#define ZCLP_UTILS
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <sys/types.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <stdexcept>

#include "../zclp++/zclp++.h"

void printu8(const uint8_t* in, size_t len);

void shift_right(uint8_t* data, size_t len, unsigned shift);

void shift_left(uint8_t* data, size_t len, unsigned shift);

namespace zclp_parsing {

bool is_long_header(uint8_t first_byte);

bool is_short_header(uint8_t first_byte);

}  // namespace zclp_parsing

namespace zclp_encoding {

size_t get_vl_len(const uint8_t* in);

EncodingResult encode_vl_integer(const VariableLengthInteger& in,
                                 uint8_t*& out);

EncodingResult decode_vl_integer(uint8_t* in, VariableLengthInteger& out);
EncodingResult encode_stateless_reset(const Packets::StatelessReset& in,
                                      uint8_t*& out);

EncodingResult decode_stateless_reset(uint8_t* in, size_t in_len,
                                      Packets::StatelessReset& out);

EncodingResult encode_version_negotiation(const Packets::VersionNegotiation& in,
                                          uint8_t*& out);
EncodingResult decode_version_negotiation(uint8_t* in, size_t in_len,
                                          Packets::VersionNegotiation& out);

EncodingResult encode_long_header(const Packets::LongHeader& in, uint8_t*& out);

EncodingResult decode_long_header(uint8_t* in, size_t in_len,
                                  Packets::LongHeader& out);

EncodingResult encode_protected_long_header(
    const Packets::ProtectedLongHeader& in, uint8_t*& out);

EncodingResult decode_protected_long_header(uint8_t* in, size_t in_len,
                                            Packets::ProtectedLongHeader& out);

EncodingResult encode_initial_packet(const Packets::Initial& in, uint8_t*& out);

EncodingResult decode_initial_packet(uint8_t* in, size_t in_len,
                                     Packets::Initial& out);

EncodingResult encode_0rtt_packet(const Packets::ZeroRTT& in, uint8_t*& out);

EncodingResult decode_0rtt_packet(uint8_t* in, size_t in_len,
                                  Packets::ZeroRTT& out);

EncodingResult encode_handshake_packet(const Packets::HandShake& in,
                                       uint8_t*& out);

EncodingResult decode_handshake_packet(uint8_t* in, size_t in_len,
                                       Packets::Initial& out);

EncodingResult encode_retry_packet(const Packets::Retry& in, uint8_t*& out);

EncodingResult decode_retry_packet(uint8_t* in, size_t in_len,
                                   Packets::Initial& out);

EncodingResult encode_short_header(const Packets::ShortHeader& in,
                                   uint8_t*& out);

EncodingResult decode_short_header(uint8_t* in, size_t in_len,
                                   Packets::Initial& out);

}  // namespace zclp_encoding

namespace zclp_tls {

/*
QUIC packets have varying protections depending on their type:

Version Negotiation packets have no cryptographic protection.

Retry packets use AEAD_AES_128_GCM to provide protection against accidental
modification and to limit the entities that can produce a valid Retry; see
Section 5.8.

Initial packets use AEAD_AES_128_GCM with keys derived from the
Destination Connection ID field of the first Initial packet sent by the client;
see Section 5.2.

All other packets have strong cryptographic protections for
confidentiality and integrity, using keys and algorithms negotiated by TLS.
*/

enum HP_KEY_TYPE : uint8_t {
    CLIENT = 0,
    SERVER = 1,
};

std::vector<uint8_t> hkdf_extract(const std::vector<uint8_t>& salt,
                                  const std::vector<uint8_t>& ikm);

std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& prk,
                                       const std::string& label, size_t length);

std::vector<uint8_t> derive_hp_key(const std::vector<uint8_t>& dst_connection_id,
                                   HP_KEY_TYPE type);

void print_hex(const unsigned char* data, size_t length);

void init();

[[nodiscard]] bool gen_random_data_32(uint8_t* buffer, size_t len);

struct encrypt_result {
    uint8_t* result = nullptr;
    size_t len = 0;

    ~encrypt_result();
};

encrypt_result* encrypt_(EVP_PKEY* public_key, uint8_t* data, size_t len);

encrypt_result* decrypt_(EVP_PKEY* private_key, uint8_t* data, size_t len);

EVP_PKEY* load_public_key();

EVP_PKEY* load_private_key();

EVP_PKEY* generate_rsa_key(int bits);

bool save_private_key(EVP_PKEY* pkey, const char* filename);
bool save_public_key(EVP_PKEY* pkey, const char* filename);

struct key_bytes {
    uint8_t* result = nullptr;
    size_t len = 0;

    ~key_bytes();
};

struct zclp_tls_arena {
  private:
    EVP_PKEY* public_key;
    EVP_PKEY* private_key;

  public:
    [[nodiscard]] zclp_tls_arena();

    void strip_pem_formatting(uint8_t* buffer, size_t& length);
    [[nodiscard]] key_bytes* pub_key_to_bytes() const;

    [[nodiscard]] key_bytes* private_key_to_bytes() const;

    [[nodiscard]] bool load_keys();

    ~zclp_tls_arena();
};
constexpr size_t PACKET_NUMBER_MAX_LENGTH = 4;
constexpr size_t SAMPLE_LENGTH = 16;
constexpr size_t MASK_LENGTH = 5;

struct MaskResult {
    bool success;
    std::array<uint8_t, MASK_LENGTH> mask;

    MaskResult();
    MaskResult(const MaskResult& other);
    MaskResult(bool success, std::array<uint8_t, MASK_LENGTH> mask);

    explicit operator bool() const { return success; }
    bool operator!() { return success != false; }
};

MaskResult generate_mask(const std::array<uint8_t, 16>& hp_key,
                         const std::vector<uint8_t>& sample);
bool apply_header_protection(std::vector<uint8_t>& header,
                             const std::vector<uint8_t>& sample,
                             const std::array<uint8_t, 16>& hp_key);

bool remove_header_protection(std::vector<uint8_t>& header,
                              const std::vector<uint8_t>& sample,
                              const std::array<uint8_t, 16>& hp_key);
std::vector<uint8_t> serialize_long_header(const Packets::LongHeader& hdr);

std::vector<uint8_t> serialize_short_header(const Packets::ShortHeader& hdr);

}  // namespace zclp_tls

namespace zclp_test_heplers {

/*
    2 separate methods for connection & version IDs
    in case if types would change in the future
*/

std::vector<uint8_t> u32ToVecU8(uint32_t value);

uint64_t getSpecifiedDistribution(uint64_t a, uint64_t b);

uint32_t getRandomVersionID();

uint32_t getRandomConnectionID();

std::vector<uint32_t> getRandomSupportedVersions(size_t count);

int getRandomBit();

uint64_t getRandomValidValue();

uint8_t getRandomPacketType();

uint8_t getRandomProtectedBits();

uint8_t getRandomReservedBits();

uint8_t getRandomPacketNumberLength();

uint32_t getRandomPacketNumber();

void fill_random(uint8_t* data, size_t len);

void fill_stateless_reset(Packets::StatelessReset& st);

void print_array(const uint8_t* data, size_t len);

}  // namespace zclp_test_heplers

namespace zclp_uint {

uint32_t u64_rand();

uint32_t u32_rand();

uint32_t u16_rand();

uint32_t u8_rand();

}  // namespace zclp_uint

namespace zclp_session {
bool create_session_token();
bool validate_session_token();
bool revoke_session_token();
}  // namespace zclp_session
#endif  // ZCLP_UTILS
