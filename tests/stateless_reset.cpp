#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(StatelessResetTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    for (int i = 0; i < 1000000; i++) {
        Packets::StatelessReset st;
        zclp_test_heplers::fill_stateless_reset(st);
        st.unpredictable_bits = getRandomValidValue();
        st.header_form = getRandomBit();
        st.fixed_bit = getRandomBit();
        uint8_t* encoded_buffer = nullptr;
        auto enc_res =
            zclp_encoding::encode_stateless_reset(st, encoded_buffer);
        ASSERT_TRUE(enc_res.success);
        ASSERT_GT(enc_res.len, 0u);
        Packets::StatelessReset st_decoded;
        auto dec_res = zclp_encoding::decode_stateless_reset(
            encoded_buffer, enc_res.len, st_decoded);
        ASSERT_TRUE(dec_res.success);
        ASSERT_EQ(st.header_form, st_decoded.header_form);
        ASSERT_EQ(st.fixed_bit, st_decoded.fixed_bit);
        ASSERT_EQ(st.unpredictable_bits(), st_decoded.unpredictable_bits());
        for (size_t j = 0; j < sizeof(st.reset_token); ++j) {
            ASSERT_EQ(st.reset_token[j], st_decoded.reset_token[j]);
        }
        delete[] encoded_buffer;
        encoded_buffer = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
