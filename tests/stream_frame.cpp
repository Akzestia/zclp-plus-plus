#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(StreamFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    using namespace Frames;

    for (int i = 0; i < 1000000; i++) {
        Stream _in(getSpecifiedDistribution(1000, 1500)), _out;
        _in.stream_id = getRandomValidValue();
        _in.off = getRandomBit();
        _in.len = getRandomBit();
        _in.fin = getRandomBit();
        fill_random(_in.stream_data, _in.length);
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

        ASSERT_EQ(_in.unused, _out.unused);
        ASSERT_EQ(_in.off, _out.off);
        ASSERT_EQ(_in.len, _out.len);
        ASSERT_EQ(_in.fin, _out.fin);
        ASSERT_EQ(_in.stream_id, _out.stream_id);
        ASSERT_EQ(_in.length, _out.length);
        ASSERT_TRUE(std::memcmp(_in.stream_data, _out.stream_data, _in.length)
                    == 0);

        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
