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
    std::uniform_int_distribution<uint8_t> dist(0, 3);
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
}  // namespace

TEST(LongHeaderTest, EncodeDecode) {
    using namespace Packets;

    for (int i = 0; i < 1000000; i++) {
        Packets::LongHeader lh;
        lh.header_form = getRandomBit();
        lh.fixed_bit = getRandomBit();
        lh.packet_type = getRandomPacketType();
        lh.reserved_bits = getRandomReservedBits();
        lh.packet_number_length = getRandomPacketNumberLength();
        lh.version_id = getRandomVersionID();
        lh.destination_connection_id = getRandomConnectionID();
        lh.source_connection_id = getRandomConnectionID();

        uint8_t* encoded_buffer = nullptr;
        auto enc_res = zclp_encoding::encode_long_header(lh, encoded_buffer);
        ASSERT_TRUE(enc_res.success);
        ASSERT_GT(enc_res.len, 0u);

        Packets::LongHeader lh_decoded;
        auto dec_res = zclp_encoding::decode_long_header(
            encoded_buffer, enc_res.len, lh_decoded);
        ASSERT_TRUE(dec_res.success);

        ASSERT_EQ(lh.header_form, lh_decoded.header_form);
        ASSERT_EQ(lh.fixed_bit, lh_decoded.fixed_bit);
        ASSERT_EQ(lh.packet_type, lh_decoded.packet_type);
        ASSERT_EQ(lh.reserved_bits, lh_decoded.reserved_bits);
        ASSERT_EQ(lh.packet_number_length, lh_decoded.packet_number_length);
        ASSERT_EQ(lh.version_id, lh_decoded.version_id);
        ASSERT_EQ(lh.destination_connection_id,
                  lh_decoded.destination_connection_id);
        ASSERT_EQ(lh.source_connection_id, lh_decoded.source_connection_id);

        delete[] encoded_buffer;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
