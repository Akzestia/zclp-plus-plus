#ifndef ZCLP_UTILS
#define ZCLP_UTILS
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>

#include "../zclp++.hpp"

inline void printu8(const uint8_t* in, size_t len) {
    for (size_t i = 0; i < len; i++) {
        for (int j = 7; j >= 0; j--) {
            int bit = (in[i] >> j) & 1;
            printf("[%i]", bit);
        }
        printf("\n");
    }
    printf("\n");
}

inline void shift_right(uint8_t* data, size_t len, unsigned shift) {
    if (shift == 0 || len == 0)
        return;
    for (ssize_t i = len - 1; i >= 0; i--) {
        uint8_t left_carry = 0;
        if (i > 0)
            left_carry = data[i - 1] << (8 - shift);
        data[i] = (data[i] >> shift) | left_carry;
    }
}

inline void shift_left(uint8_t* data, size_t len, unsigned shift) {
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

inline bool is_long_header(uint8_t first_byte) {
    return (first_byte & 0x80) == 1 && ((first_byte & 0x40) == 1);
}

inline bool is_short_header(uint8_t first_byte) {
    return (first_byte & 0x80) == 0 && ((first_byte & 0x40) == 1);
}

}  // namespace zclp_parsing

namespace zclp_encoding {
struct EncodingResult {
    bool success;
    size_t len;
};

inline size_t get_vl_len(const uint8_t* in) {
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

inline EncodingResult encode_vl_integer(const VariableLengthInteger& in,
                                        uint8_t*& out) {
    size_t len = in.size();
    uint64_t value = in();
    out = new uint8_t[len]();

    for (size_t i = 0; i < len; i++)
        out[i] = (value >> ((len - 1 - i) * 8)) & 0xFF;

    out[0] |= (in.len_() << 6);

    return {true, len};
}

inline EncodingResult decode_vl_integer(uint8_t* in,
                                        VariableLengthInteger& out) {
    uint64_t value = 0;
    size_t len = get_vl_len(in);

    in[0] &= 0b00111111;

    for (size_t i = 0; i < len; i++)
        value |= (static_cast<uint64_t>(in[i]) << ((len - 1 - i) * 8));

    out = VariableLengthInteger(value);
    return {true, out.size()};
}

inline EncodingResult encode_stateless_reset(const Packets::StatelessReset& in,
                                             uint8_t*& out) {
    size_t len = in.byte_size();
    out = new uint8_t[len]();

    uint8_t* vl_out;
    auto enc_res = encode_vl_integer(in.unpredictable_bits, vl_out);

    for (int i = 0; i < enc_res.len; i++)
        memcpy(out + i + 1, &vl_out[i], 1);
    memcpy(out + enc_res.len + 1, in.reset_token, 16);
    shift_left(out, len, 6);
    out[0] |= (in.header_form << 7);
    out[0] |= (in.fixed_bit << 6);
    delete[] vl_out;
    vl_out = nullptr;
    return {true, len};
}

inline EncodingResult decode_stateless_reset(uint8_t* in, size_t in_len,
                                             Packets::StatelessReset& out) {
    uint8_t HF = ((in[0] >> 7) & 1);
    uint8_t FB = ((in[0] >> 6) & 1);

    out.header_form = HF;
    out.fixed_bit = FB;

    shift_right(in, in_len, 6);

    VariableLengthInteger vl_out;
    decode_vl_integer(in + 1, vl_out);

    out.unpredictable_bits = vl_out;

    size_t token_offset = in_len - 16;

    for (int i = token_offset; i < in_len; i++) {
        uint8_t token_value = in[i];
        out.reset_token[i - token_offset] = token_value;
    }
    return {true, in_len};
}

inline EncodingResult encode_version_negotiation(
    const Packets::VersionNegotiation& in, uint8_t*& out) {
    size_t len = in.byte_size();
    out = new uint8_t[len]();

    uint8_t* version_id = reinterpret_cast<uint8_t*>(in.version_id);
    uint8_t* destination_connection_id =
        reinterpret_cast<uint8_t*>(in.destination_connection_id);
    uint8_t* source_connection_id =
        reinterpret_cast<uint8_t*>(in.source_connection_id);
    uint8_t offset = 0;
    // 4 - bytes u32
    for (int i = 0; i < 4; i++)
        memcpy(out + i + offset++, &version_id[i], 4);
    for (int i = 0; i < 4; i++)
        memcpy(out + i + offset++, &destination_connection_id[i], 4);
    for (int i = 0; i < 4; i++)
        memcpy(out + i + offset++, &destination_connection_id[i], 4);

    return EncodingResult();
}

inline EncodingResult decode_version_negotiation(
    uint8_t* in, size_t in_len, Packets::VersionNegotiation& out) {
    return EncodingResult();
}

inline EncodingResult encode_long_header(const Packets::LongHeader& in,
                                         uint8_t* out) {
    return EncodingResult();
}

inline EncodingResult encode_protected_long_header(
    const Packets::ProtectedLongHeader& in, uint8_t* out) {
    return EncodingResult();
}

inline EncodingResult encode_initial_packet(const Packets::Initial& in,
                                            uint8_t* out) {
    return EncodingResult();
}

inline EncodingResult encode_0rtt_packet(const Packets::ZeroRTT& in,
                                         uint8_t* out) {
    return EncodingResult();
}

inline EncodingResult encode_handshake_packet(const Packets::HandShake& in,
                                              uint8_t* out) {
    return EncodingResult();
}

inline EncodingResult encode_retry_packet(const Packets::Retry& in,
                                          uint8_t* out) {
    return EncodingResult();
}

inline EncodingResult encode_short_header(const Packets::ShortHeader& in,
                                          uint8_t* out) {
    return EncodingResult();
}

}  // namespace zclp_encoding

namespace zclp_tls {

/*
    Default location for self-signed certs
*/
inline const char* CERT_STORE_PRIVATE = "user/certs/private_key.pem";
inline const char* CERT_STORE_PUBLIC = "user/certs/public_key.pem";

inline void print_hex(const unsigned char* data, size_t length) {
    for (size_t i = 0; i < length; ++i)
        printf("%02x", data[i]);
    printf("\n");
}

inline void init() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

[[nodiscard]] inline bool gen_random_data_32(uint8_t* buffer, size_t len) {
    if (RAND_bytes(buffer, len) != 1)
        return false;
    return true;
}

struct encrypt_result {
    uint8_t* result = nullptr;
    size_t len = 0;

    ~encrypt_result() {
        if (result)
            delete[] result;
    }
};

inline encrypt_result* encrypt_(EVP_PKEY* public_key, uint8_t* data,
                                size_t len) {
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

inline encrypt_result* decrypt_(EVP_PKEY* private_key, uint8_t* data,
                                size_t len) {
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

inline EVP_PKEY* load_public_key() {
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

inline EVP_PKEY* load_private_key() {
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

inline EVP_PKEY* generate_rsa_key(int bits) {
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

inline bool save_private_key(EVP_PKEY* pkey, const char* filename) {
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

inline bool save_public_key(EVP_PKEY* pkey, const char* filename) {
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

struct key_bytes {
    uint8_t* result = nullptr;
    size_t len = 0;

    ~key_bytes() {
        if (result)
            delete[] result;
    }
};

struct zclp_tls_arena {
  private:
    EVP_PKEY* public_key;
    EVP_PKEY* private_key;

  public:
    [[nodiscard]] zclp_tls_arena() {
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

    void strip_pem_formatting(uint8_t* buffer, size_t& length) {
        const uint8_t* begin = static_cast<const uint8_t*>(
            memmem(buffer, length, "-----BEGIN", 10));
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

    [[nodiscard]] key_bytes* pub_key_to_bytes() const {
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

    [[nodiscard]] key_bytes* private_key_to_bytes() const {
        if (!private_key)
            return nullptr;

        BIO* bio = BIO_new(BIO_s_mem());
        if (bio == nullptr)
            throw "Failed to create BIO";

        if (PEM_write_bio_PrivateKey(bio, private_key, nullptr, nullptr, 0,
                                     nullptr, nullptr)
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

    [[nodiscard]] bool load_keys() {
        public_key = load_public_key();
        if (!public_key)
            return false;
        private_key = load_private_key();
        if (!private_key)
            return false;
        return true;
    }

    ~zclp_tls_arena() {
        EVP_PKEY_free(public_key);
        EVP_PKEY_free(private_key);
    }
};

}  // namespace zclp_tls

namespace zclp_test_heplers {

inline void fill_random(uint8_t* data, size_t len) {
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 255);

    for (size_t i = 0; i < len; ++i) {
        data[i] = static_cast<uint8_t>(dist(engine));
    }
}

inline void fill_stateless_reset(Packets::StatelessReset& st) {
    fill_random(st.reset_token, sizeof(st.reset_token));
}

inline void print_array(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("[%i]", data[i]);
        if ((i + 1) % 8 == 0)
            printf("\n");
    }
    if (len % 8 != 0)
        printf("\n");
}

}  // namespace zclp_test_heplers

#endif  // ZCLP_UTILS
