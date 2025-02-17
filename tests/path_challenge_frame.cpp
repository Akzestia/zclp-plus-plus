#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(PathChallangeFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_uint;
    using namespace Frames;

    for (int i = 0; i < 100; i++) {
        PathChallange _in, _out;
        _in.data = u64_rand();
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
        ASSERT_EQ(_in.data, _out.data);

        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
