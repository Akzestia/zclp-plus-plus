#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(ClusterMaskFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    using namespace Frames;

    for (int i = 0; i < 100; i++) {
        ClusterMask _in(getSpecifiedDistribution(16, 32)), _out;

        uint8_t* out = new uint8_t[_in.byte_size()]();
        fill_random(_in.mask, _in.mask_length);

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
        ASSERT_EQ(_in.mask_length, _out.mask_length);
        ASSERT_TRUE(std::memcmp(_in.mask, _out.mask, _in.mask_length) == 0);

        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
