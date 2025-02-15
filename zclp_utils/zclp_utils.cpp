#include "zclp_utils.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

void printu8(const uint8_t* in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        for (int j = 7; j >= 0; j--) {
            int bit = (in[i] >> j) & 1;
            printf("[%i]", bit);
        }
        printf("\n");
    }
    printf("\n");
}

void shift_right(uint8_t* data, size_t len, unsigned shift) {
    if (shift == 0 || len == 0)
        return;
    for (ssize_t i = len - 1; i >= 0; i--) {
        uint8_t left_carry = 0;
        if (i > 0)
            left_carry = data[i - 1] << (8 - shift);
        data[i] = (data[i] >> shift) | left_carry;
    }
}

void shift_left(uint8_t* data, size_t len, unsigned shift) {
    if (shift == 0 || len == 0)
        return;
    for (size_t i = 0; i < len; i++) {
        uint8_t right_carry = 0;
        if (i < len - 1)
            right_carry = data[i + 1] >> (8 - shift);
        data[i] = (data[i] << shift) | right_carry;
    }
}

namespace zclp_parsing {

bool is_long_header(uint8_t first_byte) {
    return (first_byte & 0x80) == 1 && ((first_byte & 0x40) == 1);
}

bool is_short_header(uint8_t first_byte) {
    return (first_byte & 0x80) == 0 && ((first_byte & 0x40) == 1);
}

}  // namespace zclp_parsing

namespace zclp_encoding {

size_t get_vl_len(const uint8_t* in) {
    uint8_t first_byte = in[0];
    uint8_t len_indicator = first_byte >> 6;

    switch (len_indicator) {
    case 0:
        return 1;
    case 1:
        return 2;
    case 2:
        return 4;
    case 3:
        return 8;
    default:
        return -1;
    }
};

EncodingResult encode_vl_integer(const VariableLengthInteger& in,
                                 uint8_t*& out) {
    size_t len = in.byte_size();
    uint64_t value = in();

    for (size_t i = 0; i < len; i++)
        out[i] = (value >> ((len - 1 - i) * 8)) & 0xFF;

    out[0] |= (in.len_() << 6);

    return {true, len};
}

EncodingResult decode_vl_integer(uint8_t* in, VariableLengthInteger& out) {
    uint64_t value = 0;
    // printu8(in, 1);
    size_t len = get_vl_len(in);

    in[0] &= 0b00111111;

    for (size_t i = 0; i < len; i++)
        value |= (static_cast<uint64_t>(in[i]) << ((len - 1 - i) * 8));

    out = VariableLengthInteger(value);
    return {true, out.byte_size()};
}

EncodingResult encode_stateless_reset(const Packets::StatelessReset& in,
                                      uint8_t*& out) {
    size_t offset = 1;
    size_t len = in.byte_size();
    out = new uint8_t[len]();
    uint8_t* vl_out = out + offset;
    auto enc_res = encode_vl_integer(in.unpredictable_bits, vl_out);
    if (!enc_res) {
        vl_out = nullptr;
        return {enc_res, enc_res.len};
    }
    offset += enc_res.len;
    vl_out = nullptr;

    uint8_t* reset_token_ref = out + offset;
    memcpy(reset_token_ref, in.reset_token, 16);
    reset_token_ref = nullptr;
    shift_left(out, len, 6);

    out[0] |= (in.header_form << 7);
    out[0] |= (in.fixed_bit << 6);
    return {true, len};
}

EncodingResult decode_stateless_reset(uint8_t* in, size_t in_len,
                                      Packets::StatelessReset& out) {
    size_t offset = 0;

    out.header_form = ((in[offset] >> 7) & 1);
    out.fixed_bit = ((in[offset++] >> 6) & 1);

    shift_right(in, in_len, 6);

    uint8_t* d_res_unpredictable_bits_ref = in + offset;
    auto res_unpredictable_bits = zclp_encoding::decode_vl_integer(
        d_res_unpredictable_bits_ref, out.unpredictable_bits);
    if (!res_unpredictable_bits) {
        d_res_unpredictable_bits_ref = nullptr;
        return res_unpredictable_bits;
    }
    offset += res_unpredictable_bits.len;
    d_res_unpredictable_bits_ref = nullptr;

    uint8_t* d_reset_token_ref = in + offset;
    memcpy(&out.reset_token, d_reset_token_ref, 16);
    return {true, in_len};
}

EncodingResult encode_version_negotiation(const Packets::VersionNegotiation& in,
                                          uint8_t*& out) {
    size_t len = in.byte_size();
    out = new uint8_t[len]();
    uint8_t offset = 1;
    // 4 - bytes u32
    memcpy(out + offset, &in.version_id, 4);
    offset += 4;
    memcpy(out + offset, &in.destination_connection_id, 4);
    offset += 4;
    memcpy(out + offset, &in.source_connection_id, 4);
    offset += 4;
    for (int i = 0; i < in.supported_versions.size(); i++) {
        memcpy(out + offset, &in.supported_versions[i], 4);
        offset += 4;
    }

    shift_left(out, len, 1);
    out[0] |= (in.header_form << 7);
    out[0] |= (in.unused << 1);

    return {true, len};
}

EncodingResult decode_version_negotiation(uint8_t* in, size_t in_len,
                                          Packets::VersionNegotiation& out) {
    size_t offset = 1;

    out.header_form = ((in[0] >> 7) & 1);
    out.unused = (in[0] >> 1) & 0x3F;

    shift_right(in, in_len, 1);

    memcpy(&out.version_id, in + offset, 4);
    offset += 4;

    memcpy(&out.destination_connection_id, in + offset, 4);
    offset += 4;

    memcpy(&out.source_connection_id, in + offset, 4);
    offset += 4;

    int supported_versions_size = (in_len - offset) / 4;

    out.supported_versions.resize(supported_versions_size);

    for (int i = 0; i < supported_versions_size; i++) {
        memcpy(&out.supported_versions[i], in + offset, 4);
        offset += 4;
    }

    return {true, in_len};
}

EncodingResult encode_long_header(const Packets::LongHeader& in,
                                  uint8_t*& out) {
    size_t len = in.byte_size();
    out = new uint8_t[len]();

    out[0] |= (in.header_form << 7);
    out[0] |= (in.fixed_bit << 6);
    out[0] |= (in.packet_type << 4);
    out[0] |= (in.reserved_bits << 2);
    out[0] |= (in.packet_number_length << 0);

    size_t offset = 1;
    memcpy(out + offset, &in.version_id, 4);
    offset += 4;
    memcpy(out + offset, &in.destination_connection_id, 4);
    offset += 4;
    memcpy(out + offset, &in.source_connection_id, 4);
    offset += 4;
    return {true, len};
}

EncodingResult decode_long_header(uint8_t* in, size_t in_len,
                                  Packets::LongHeader& out) {
    out.header_form = ((in[0] >> 7) & 1);
    out.fixed_bit = ((in[0] >> 6) & 1);
    out.packet_type = ((in[0] >> 4) & 0x03);
    out.reserved_bits = ((in[0] >> 2) & 0x03);
    out.packet_number_length = ((in[0] >> 0) & 0x03);

    size_t offset = 1;

    memcpy(&out.version_id, in + offset, 4);
    offset += 4;
    memcpy(&out.destination_connection_id, in + offset, 4);
    offset += 4;
    memcpy(&out.source_connection_id, in + offset, 4);

    return {true, in_len};
}

EncodingResult encode_protected_long_header(
    const Packets::ProtectedLongHeader& in, uint8_t*& out) {
    size_t len = in.byte_size();

    out = new uint8_t[len]();

    out[0] |= (in.header_form << 7);
    out[0] |= (in.fixed_bit << 6);
    out[0] |= (in.packet_type << 4);
    out[0] |= (in.protected_bits << 0);

    size_t offset = 1;
    memcpy(out + offset, &in.version_id, 4);
    offset += 4;
    memcpy(out + offset, &in.destination_connection_id, 4);
    offset += 4;
    memcpy(out + offset, &in.source_connection_id, 4);
    offset += 4;

    return {true, len};
}

EncodingResult decode_protected_long_header(uint8_t* in, size_t in_len,
                                            Packets::ProtectedLongHeader& out) {
    out.header_form = ((in[0] >> 7) & 1);
    out.fixed_bit = ((in[0] >> 6) & 1);
    out.packet_type = ((in[0] >> 4) & 0x03);
    out.protected_bits = ((in[0] >> 0) & 0x0F);

    size_t offset = 1;

    memcpy(&out.version_id, in + offset, 4);
    offset += 4;
    memcpy(&out.destination_connection_id, in + offset, 4);
    offset += 4;
    memcpy(&out.source_connection_id, in + offset, 4);

    return {true, in_len};
}

EncodingResult encode_initial_packet(const Packets::Initial& in,
                                     uint8_t*& out) {
    size_t len = in.byte_size();
    out = new uint8_t[len]();
    size_t offset = 0;

    uint8_t* ref_eader = out + offset;
    auto header_encode = encode_long_header(in.header, ref_eader);
    if (!header_encode)
        return {false, header_encode.len + offset};
    offset += header_encode.len;
    ref_eader = nullptr;

    uint8_t* ref_token_len = out + offset;
    auto token_len = encode_vl_integer(in.token_length, ref_token_len);
    if (!token_len)
        return {false, token_len.len + offset};
    offset += token_len.len;
    ref_token_len = nullptr;

    memcpy(out + offset, in.token, in.token_length());
    offset += in.token_length();

    uint8_t* ref_len = out + offset;
    auto len_ = encode_vl_integer(in.length, ref_len);
    if (!len_)
        return {false, len_.len + offset};
    offset += len_.len;
    ref_len = nullptr;
    size_t packet_number_offset = offset++;

    for (const auto& frame : in.payload) {
        auto size = Frames::frame_size(frame);
        uint8_t* frame_ref = out + offset;
        auto res = Frames::encode(frame, frame_ref);
        if (!res)
            return {false, len_.len + offset};
        memcpy(out + offset, frame_ref, res.len);
        offset += res.len;
        frame_ref = nullptr;
    }

    printu8(out, len);
    uint8_t* ref_shift = out + packet_number_offset;
    shift_left(ref_shift, in.length, 5);
    out[packet_number_offset] |= (in.packet_number << 5);
    ref_shift = nullptr;

    return {true, len};
}

EncodingResult decode_initial_packet(uint8_t* in, size_t in_len,
                                     Packets::Initial& out) {
    size_t offset = 0;

    auto d_lheader = decode_long_header(in, out.header.byte_size(), out.header);
    if (!d_lheader)
        return {false, offset};
    offset += d_lheader.len;
    uint8_t* d_token_len_ref = in + offset;
    auto d_token_len =
        zclp_encoding::decode_vl_integer(d_token_len_ref, out.token_length);
    if (!d_token_len) {
        d_token_len_ref = nullptr;
        return {false, offset};
    }
    offset += d_token_len.len;
    d_token_len_ref = nullptr;

    uint8_t* d_token_ref = in + offset;
    memcpy(out.token, d_token_ref, out.token_length());
    offset += out.token_length();
    d_token_ref = nullptr;

    uint8_t* d_len_ref = in + offset;
    ;

    auto d_len = zclp_encoding::decode_vl_integer(d_len_ref, out.length);
    if (!d_len) {
        d_len_ref = nullptr;
        return {false, offset};
    }
    offset += d_len.len;
    d_len_ref = nullptr;

    uint8_t* d_packet_number_ref = in + offset++;
    out.packet_number = (d_packet_number_ref[0] >> 5) & 0b111;
    shift_right(d_packet_number_ref, out.length, 5);
    d_packet_number_ref = nullptr;
    printu8(in, in_len);

    size_t payload_size = out.length - 1, d_payload_size = 0;
    while (d_payload_size < payload_size) {
        uint8_t* d_payload_ref = in + offset;
        Frames::FrameVariant fv;
        auto fv_res = Frames::decode(d_payload_ref, fv);
        if (!fv_res) {
            d_payload_ref = nullptr;
            return {false, fv_res.len};
        }
        out.add_frame(fv, 0);
        offset += fv_res.len;
        d_payload_size += fv_res.len;
        d_payload_ref = nullptr;
    }

    return {true, in_len};
}

EncodingResult encode_0rtt_packet(const Packets::ZeroRTT& in, uint8_t*& out) {
    size_t len = in.byte_size();

    return {true, len};
}

EncodingResult decode_0rtt_packet(uint8_t* in, size_t in_len,
                                  Packets::ZeroRTT& out) {
    return {true, in_len};
}

EncodingResult encode_handshake_packet(const Packets::HandShake& in,
                                       uint8_t*& out) {
    size_t len = in.byte_size();

    return {true, len};
}

EncodingResult decode_handshake_packet(uint8_t* in, size_t in_len,
                                       Packets::Initial& out) {
    return {true, in_len};
}

EncodingResult encode_retry_packet(const Packets::Retry& in, uint8_t*& out) {
    size_t len = in.byte_size();

    return {true, len};
}

EncodingResult decode_retry_packet(uint8_t* in, size_t in_len,
                                   Packets::Initial& out) {
    return {true, in_len};
}

EncodingResult encode_short_header(const Packets::ShortHeader& in,
                                   uint8_t*& out) {
    size_t len = in.byte_size();

    return {true, len};
}

EncodingResult decode_short_header(uint8_t* in, size_t in_len,
                                   Packets::Initial& out) {
    return {true, in_len};
}

}  // namespace zclp_encoding

namespace zclp_tls {

/*
    Default location for self-signed certs
*/
const char* CERT_STORE_PRIVATE = "user/certs/private_key.pem";
const char* CERT_STORE_PUBLIC = "user/certs/public_key.pem";

void print_hex(const unsigned char* data, size_t length) {
    for (size_t i = 0; i < length; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

void init() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

[[nodiscard]] bool gen_random_data_32(uint8_t* buffer, size_t len) {
    if (RAND_bytes(buffer, len) != 1)
        return false;
    return true;
}

encrypt_result::~encrypt_result() {
    if (result)
        delete[] result;
}

encrypt_result* encrypt_(EVP_PKEY* public_key, uint8_t* data, size_t len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key, nullptr);
    if (!ctx) {
        return nullptr;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen,
                         reinterpret_cast<const unsigned char*>(data), len)
        <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    uint8_t* encrypted_data = new uint8_t[outlen]();
    if (EVP_PKEY_encrypt(ctx, encrypted_data, &outlen,
                         reinterpret_cast<const unsigned char*>(data), len)
        <= 0) {
        delete[] encrypted_data;
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return new encrypt_result{encrypted_data, outlen};
}

encrypt_result* decrypt_(EVP_PKEY* private_key, uint8_t* data, size_t len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) {
        return nullptr;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, data, len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    uint8_t* decrypted_data = new uint8_t[outlen]();
    if (EVP_PKEY_decrypt(ctx, decrypted_data, &outlen, data, len) <= 0) {
        delete[] decrypted_data;
        return nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    return new encrypt_result{decrypted_data, outlen};
}

EVP_PKEY* load_public_key() {
    BIO* bio = BIO_new_file(CERT_STORE_PUBLIC, "r");
    if (!bio) {
        printf("Failed to open private key file\n");
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!key) {
        printf("Failed to read private key\n");
        BIO_free(bio);
        return nullptr;
    }
    return key;
}

EVP_PKEY* load_private_key() {
    BIO* bio = BIO_new_file(CERT_STORE_PRIVATE, "r");
    if (!bio) {
        printf("Failed to open private key file\n");
        return nullptr;
    }

    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!key) {
        printf("Failed to read private key\n");
        BIO_free(bio);
        return nullptr;
    }
    return key;
}

EVP_PKEY* generate_rsa_key(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        perror("Failed: context");
        return nullptr;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        perror("Failed: context init");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        perror("Failed: context key_gen_info");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        perror("Failed: key_gen");
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

bool save_private_key(EVP_PKEY* pkey, const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        printf("Failed to open file:  %s", filename);
        return false;
    }

    if (PEM_write_PrivateKey(fp, pkey, nullptr, nullptr, 0, nullptr, nullptr)
        != 1) {
        printf("Failed to write private key to file");
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

bool save_public_key(EVP_PKEY* pkey, const char* filename) {
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        printf("Failed to open file:  %s", filename);
        return false;
    }

    if (PEM_write_PUBKEY(fp, pkey) != 1) {
        printf("Failed to write public key to file");
        fclose(fp);
        return false;
    }

    fclose(fp);
    return true;
}

key_bytes::~key_bytes() {
    if (result)
        delete[] result;
}

[[nodiscard]] zclp_tls_arena::zclp_tls_arena() {
    if (!load_keys()) {
        EVP_PKEY* key = zclp_tls::generate_rsa_key(2048);
        zclp_tls::save_private_key(key, zclp_tls::CERT_STORE_PRIVATE);
        zclp_tls::save_public_key(key, zclp_tls::CERT_STORE_PUBLIC);

        EVP_PKEY_free(key);

        if (!load_keys())
            throw "Failed to load RSA key pair";
        else
            printf("Successfully loaded RSA key pair\n");
        return;
    }
    printf("Successfully loaded RSA key pair\n");
}

void zclp_tls_arena::strip_pem_formatting(uint8_t* buffer, size_t& length) {
    const uint8_t* begin =
        static_cast<const uint8_t*>(memmem(buffer, length, "-----BEGIN", 10));
    const uint8_t* end =
        static_cast<const uint8_t*>(memmem(buffer, length, "-----END", 8));

    if (!begin || !end)
        return;

    begin = static_cast<const uint8_t*>(memchr(begin, '\n', end - begin));
    if (!begin)
        return;
    begin++;

    uint8_t* temp = new uint8_t[length];
    size_t pos = 0;

    while (begin < end) {
        if (*begin != '\n' && *begin != '\r') {
            temp[pos++] = *begin;
        }
        begin++;
    }
    memcpy(buffer, temp, pos);
    length = pos;
    delete[] temp;
}

[[nodiscard]] key_bytes* zclp_tls_arena::pub_key_to_bytes() const {
    if (!public_key)
        return nullptr;

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr)
        throw "Failed to create BIO";

    if (PEM_write_bio_PUBKEY(bio, public_key) == 0) {
        BIO_free(bio);
        throw "Failed to write EVP_PKEY to BIO";
    }

    size_t key_len = BIO_pending(bio);
    uint8_t* key_data = new uint8_t[key_len]();

    if (BIO_read(bio, key_data, key_len) <= 0) {
        delete[] key_data;
        BIO_free(bio);
        throw "Failed to read data from BIO";
    }

    BIO_free(bio);
    return new key_bytes{key_data, key_len};
}

[[nodiscard]] key_bytes* zclp_tls_arena::private_key_to_bytes() const {
    if (!private_key)
        return nullptr;

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr)
        throw "Failed to create BIO";

    if (PEM_write_bio_PrivateKey(bio, private_key, nullptr, nullptr, 0, nullptr,
                                 nullptr)
        == 0) {
        BIO_free(bio);
        throw "Failed to write EVP_PKEY to BIO";
    }

    size_t key_len = BIO_pending(bio);
    uint8_t* key_data = new uint8_t[key_len]();

    if (BIO_read(bio, key_data, key_len) <= 0) {
        delete[] key_data;
        BIO_free(bio);
        throw "Failed to read data from BIO";
    }

    BIO_free(bio);
    return new key_bytes{key_data, key_len};
}

[[nodiscard]] bool zclp_tls_arena::load_keys() {
    public_key = load_public_key();
    if (!public_key)
        return false;
    private_key = load_private_key();
    if (!private_key)
        return false;
    return true;
}

zclp_tls_arena::~zclp_tls_arena() {
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
}

MaskResult::MaskResult() : success(false), mask({}) {
}
MaskResult::MaskResult(const MaskResult& other)
    : success(other.success), mask(other.mask) {
}
MaskResult::MaskResult(bool success, std::array<uint8_t, MASK_LENGTH> mask)
    : success(success), mask(mask) {
}

constexpr std::array<uint8_t, 20> quic_v1_salt = {
    0xef, 0x4f, 0x5f, 0x57, 0x84, 0x90, 0xa3, 0x68, 0x9c, 0x76,
    0x6b, 0xee, 0xfd, 0x4a, 0x2a, 0xe6, 0x0a, 0x44, 0x9f, 0x17};

MaskResult generate_mask(const std::array<uint8_t, 16>& hp_key,
                         const std::vector<uint8_t>& sample) {
    if (sample.size() < SAMPLE_LENGTH) {
        return MaskResult();
    }

    std::array<uint8_t, MASK_LENGTH> mask = {};
    std::array<uint8_t, 16> counter_block = {};

    std::memcpy(counter_block.data(), sample.data(),
                std::min(sample.size(), counter_block.size()));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        EVP_CIPHER_CTX_free(ctx);
        return MaskResult();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, hp_key.data(),
                           counter_block.data())
        != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MaskResult();
    }

    int outlen = 0;
    std::array<uint8_t, 16> zeros = {};
    if (EVP_EncryptUpdate(ctx, mask.data(), &outlen, zeros.data(), MASK_LENGTH)
        != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return MaskResult();
    }

    EVP_EncryptFinal_ex(ctx, nullptr, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    return MaskResult({true, mask});
}

bool apply_header_protection(std::vector<uint8_t>& header,
                             const std::vector<uint8_t>& sample,
                             const std::array<uint8_t, 16>& hp_key) {
    if (header.empty())
        return false;

    auto result = generate_mask(hp_key, sample);
    if (!result)
        return false;
    auto mask = result.mask;

    bool is_long_header = (header[0] & 0x80) != 0;

    if (is_long_header)
        header[0] ^= (mask[0] & 0x0F);
    else
        header[0] ^= (mask[0] & 0x1F);

    for (size_t i = 0; i < PACKET_NUMBER_MAX_LENGTH && (i + 1) < header.size();
         i++)
        header[i + 1] ^= mask[i + 1];
    return true;
}

bool remove_header_protection(std::vector<uint8_t>& header,
                              const std::vector<uint8_t>& sample,
                              const std::array<uint8_t, 16>& hp_key) {
    return apply_header_protection(header, sample, hp_key);
}

std::vector<uint8_t> serialize_long_header(const Packets::LongHeader& hdr) {
    std::vector<uint8_t> data(hdr.byte_size());
    data[0] = (hdr.header_form << 7) | (hdr.fixed_bit << 6)
        | (hdr.packet_type << 4) | (hdr.reserved_bits << 2)
        | hdr.packet_number_length;
    std::memcpy(&data[1], &hdr.version_id, sizeof(hdr.version_id));
    std::memcpy(&data[5], &hdr.destination_connection_id,
                sizeof(hdr.destination_connection_id));
    std::memcpy(&data[9], &hdr.source_connection_id,
                sizeof(hdr.source_connection_id));
    return data;
}

std::vector<uint8_t> serialize_short_header(const Packets::ShortHeader& hdr) {
    std::vector<uint8_t> data(hdr.byte_size());
    data[0] = (hdr.header_form << 7) | (hdr.fixed_bit << 6)
        | (hdr.spin_bit << 5) | (hdr.reserved_bits << 3) | (hdr.key_phase << 2)
        | hdr.packet_number_length;
    std::memcpy(&data[1], &hdr.destination_connection,
                sizeof(hdr.destination_connection));
    data[5] = hdr.packet_number;
    return data;
}

}  // namespace zclp_tls

namespace zclp_test_heplers {
std::mt19937_64 rng{std::random_device{}()};

/*
    2 separate methods for connection & version IDs
    in case if types would change in the future
*/

uint32_t getRandomVersionID() {
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    return dist(rng);
}

uint32_t getRandomConnectionID() {
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    return dist(rng);
}

std::vector<uint32_t> getRandomSupportedVersions(size_t count) {
    std::vector<uint32_t> versions;
    for (size_t i = 0; i < count; ++i) {
        versions.push_back(getRandomVersionID());
    }
    return versions;
}

int getRandomBit() {
    std::uniform_int_distribution<int> dist(0, 1);
    return dist(rng);
}

uint64_t getRandomValidValue() {
    static const uint64_t MAX_VALID_VALUE = 0x3FFFFFFFFFFFFFFF;
    std::uniform_int_distribution<uint64_t> dist(0, MAX_VALID_VALUE);
    return dist(rng);
}

uint8_t getRandomPacketType() {
    std::uniform_int_distribution<uint8_t> dist(0, 3);
    return dist(rng);
}

uint8_t getRandomProtectedBits() {
    std::uniform_int_distribution<uint8_t> dist(0, 15);
    return dist(rng);
}

uint8_t getRandomReservedBits() {
    std::uniform_int_distribution<uint8_t> dist(0, 3);
    return dist(rng);
}

uint8_t getRandomPacketNumberLength() {
    std::uniform_int_distribution<uint8_t> dist(0, 3);
    return dist(rng);
}

uint32_t getRandomPacketNumber() {
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFF);
    return dist(rng);
}

void fill_random(uint8_t* data, size_t len) {
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 255);

    for (size_t i = 0; i < len; ++i) {
        data[i] = static_cast<uint8_t>(dist(engine));
    }
}

void fill_stateless_reset(Packets::StatelessReset& st) {
    fill_random(st.reset_token, sizeof(st.reset_token));
}

void print_array(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("[%i]", data[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    if (len % 8 != 0)
        printf("\n");
}

}  // namespace zclp_test_heplers

namespace zclp_uint {
std::mt19937_64 rng{std::random_device{}()};

uint32_t u64_rand() {
    std::uniform_int_distribution<uint64_t> dist(0, 0x3FFFFFFFFFFFFFFF);
    return dist(rng);
}

uint32_t u32_rand() {
    std::uniform_int_distribution<uint32_t> dist(0, 0x3FFFFFFF);
    return dist(rng);
}

uint32_t u16_rand() {
    std::uniform_int_distribution<uint16_t> dist(0, 0x3FFF);
    return dist(rng);
}

uint32_t u8_rand() {
    std::uniform_int_distribution<uint8_t> dist(0, 0x3F);
    return dist(rng);
}

}  // namespace zclp_uint

namespace zclp_session {
bool create_session_token();
bool validate_session_token();
bool revoke_session_token();
}  // namespace zclp_session
