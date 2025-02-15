#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(StopSendingFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    using namespace Frames;

    for (int i = 0; i < 1000000; i++) {
        StopSending _in, _out;

        _in.stream_id = getRandomValidValue();
        _in.error_code = getRandomValidValue();

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

        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
