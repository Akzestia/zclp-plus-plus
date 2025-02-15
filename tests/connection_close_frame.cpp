#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(ConnectionCloseFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    using namespace Frames;

    for (int i = 0; i < 1000000; i++) {
        ConnectionClose _in(getSpecifiedDistribution(16, 32)), _out;
        _in.error = getRandomValidValue();
        _in.frame_type = getRandomValidValue();

        uint8_t* out = new uint8_t[_in.byte_size()]();
        fill_random(_in.phrase, _in.phrase_len);

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
        ASSERT_EQ(_in.error, _out.error);
        ASSERT_EQ(_in.frame_type, _out.frame_type);
        ASSERT_EQ(_in.phrase_len, _out.phrase_len);
        ASSERT_TRUE(std::memcmp(_in.phrase, _out.phrase, _in.phrase_len) == 0);

        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
