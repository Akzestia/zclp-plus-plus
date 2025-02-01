#ifndef ZCLP_UTILS
#define ZCLP_UTILS
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

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

inline ParserResult<Packets::ShortHeader> parse_short_header(
    const uint8_t* data, ssize_t len);
inline ParserResult<Packets::LongHeader> parse_long_header(const uint8_t* data,
                                                           ssize_t len);

}  // namespace zclp_parsing

namespace zclp_encoding {
struct EncodingResult {
    bool success;
    size_t len;
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
#endif  // ZCLP_UTILS
