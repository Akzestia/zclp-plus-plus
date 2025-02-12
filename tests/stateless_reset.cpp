#include <gtest/gtest.h>

#include <cstdint>
#include <random>

#include "../zclp++.hpp"
#include "../zclp_utils/zclp_utils.hpp"

namespace {
std::mt19937_64 rng{std::random_device{}()};
uint64_t getRandomValidValue() {
    static const uint64_t MAX_VALID_VALUE = 0x3FFFFFFFFFFFFFFF;
    std::uniform_int_distribution<uint64_t> dist(0, MAX_VALID_VALUE);
    return dist(rng);
}
int getRandomBit() {
    std::uniform_int_distribution<int> dist(0, 1);
    return dist(rng);
}
}  // namespace

TEST(StatelessResetTest, EncodeDecode) {
    using namespace Packets;
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
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
