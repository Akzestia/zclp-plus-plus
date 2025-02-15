#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(LongHeaderTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;

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
        if (!enc_res) {
            delete[] encoded_buffer;
            encoded_buffer = nullptr;
            FAIL();
        }
        ASSERT_TRUE(enc_res.success);
        ASSERT_GT(enc_res.len, 0u);

        Packets::LongHeader lh_decoded;
        auto dec_res = zclp_encoding::decode_long_header(
            encoded_buffer, enc_res.len, lh_decoded);
        if (!dec_res) {
            delete[] encoded_buffer;
            encoded_buffer = nullptr;
            FAIL();
        }
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
        encoded_buffer = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
