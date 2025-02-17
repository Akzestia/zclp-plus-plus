#include <gtest/gtest.h>

#include <cstring>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

bool compareArrays(const uint8_t arr1[16], const uint8_t arr2[16]) {
    for (int i = 0; i < 16; ++i) {
        if (arr1[i] != arr2[i]) {
            printf("Mismatch at index %d: 0x%02x != 0x%02x\n", i, arr1[i],
                   arr2[i]);
            return false;
        }
    }
    return true;
}

TEST(NewConnectionIdFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    using namespace Frames;

    for (int i = 0; i < 100; i++) {
        NewConnectionId _in, _out;
        _in.sequence_number = getRandomValidValue();
        _in.retire_prior_to = getRandomValidValue();
        _in.connection_id = getRandomConnectionID();
        fill_random(_in.stateless_reset_token, 16);
        uint8_t* out = new uint8_t[_in.byte_size()]();

        auto enc_res = encode(_in, out);
        if (!enc_res) {
            delete[] out;
            out = nullptr;
            FAIL();
        }

        auto dec_res = decode(out, _out);
        if (!dec_res) {
            delete[] out;
            out = nullptr;
            FAIL();
        }

        ASSERT_EQ(_in.type, _out.type);
        ASSERT_EQ(_in.sequence_number, _out.sequence_number);
        ASSERT_EQ(_in.retire_prior_to, _out.retire_prior_to);
        ASSERT_EQ(_in.connection_id, _out.connection_id);
        ASSERT_TRUE(compareArrays(_in.stateless_reset_token,
                                  _out.stateless_reset_token));

        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
