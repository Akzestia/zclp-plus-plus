#include <gtest/gtest.h>
#include <sys/types.h>

#include <cstdint>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(CryptoFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    using namespace Frames;

    for (int i = 0; i < 100; i++) {
        Crypto _in(getSpecifiedDistribution(120, 1500)), _out;
        _in.offset = getRandomValidValue();

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
        ASSERT_EQ(_in.offset, _out.offset);
        ASSERT_EQ(_in.length, _out.length);
        ASSERT_TRUE(std::memcmp(_in.data, _out.data, _in.length) == 0);

        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
