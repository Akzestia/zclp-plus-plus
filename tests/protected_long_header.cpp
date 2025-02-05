#include <gtest/gtest.h>

#include <cstdint>
#include <random>

#include "../zclp++.hpp"
#include "../zclp_utils/zclp_utils.hpp"

namespace {
std::mt19937_64 rng{std::random_device{}()};

uint32_t getRandomVersionID() {
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    return dist(rng);
}

uint32_t getRandomConnectionID() {
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
    return dist(rng);
}

int getRandomBit() {
    std::uniform_int_distribution<int> dist(0, 1);
    return dist(rng);
}

uint8_t getRandomPacketType() {
    std::uniform_int_distribution<uint8_t> dist(0, 3);  // 2-bit value (0-3)
    return dist(rng);
}

uint8_t getRandomProtectedBits() {
    std::uniform_int_distribution<uint8_t> dist(0, 15);  // 4-bit value (0-15)
    return dist(rng);
}
}  // namespace

TEST(ProtectedLongHeaderTest, EncodeDecode) {
    using namespace Packets;

    for (int i = 0; i < 1000000; i++) {
        ProtectedLongHeader plh;
        plh.header_form = getRandomBit();
        plh.fixed_bit = getRandomBit();
        plh.packet_type = getRandomPacketType();
        plh.protected_bits = getRandomProtectedBits();
        plh.version_id = getRandomVersionID();
        plh.destination_connection_id = getRandomConnectionID();
        plh.source_connection_id = getRandomConnectionID();

        uint8_t* encoded_buffer = nullptr;
        auto enc_res =
            zclp_encoding::encode_protected_long_header(plh, encoded_buffer);
        ASSERT_TRUE(enc_res.success);
        ASSERT_GT(enc_res.len, 0u);

        ProtectedLongHeader plh_decoded;
        auto dec_res = zclp_encoding::decode_protected_long_header(
            encoded_buffer, enc_res.len, plh_decoded);
        ASSERT_TRUE(dec_res.success);

        ASSERT_EQ(plh.header_form, plh_decoded.header_form);
        ASSERT_EQ(plh.fixed_bit, plh_decoded.fixed_bit);
        ASSERT_EQ(plh.packet_type, plh_decoded.packet_type);
        ASSERT_EQ(plh.protected_bits, plh_decoded.protected_bits);
        ASSERT_EQ(plh.version_id, plh_decoded.version_id);
        ASSERT_EQ(plh.destination_connection_id,
                  plh_decoded.destination_connection_id);
        ASSERT_EQ(plh.source_connection_id, plh_decoded.source_connection_id);

        delete[] encoded_buffer;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
