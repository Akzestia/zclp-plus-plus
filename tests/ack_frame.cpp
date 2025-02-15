#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(AckFrameTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    using namespace Frames;

    for (int i = 0; i < 1000000; i++) {
        Ack _in, _out;
        _in.type = i % 2 == 0 ? 3 : 4;
        _in.largest_ack_num = getRandomValidValue();
        _in.delay = getRandomValidValue();
        _in.range_count = 10;

        for (int j = 0; j < _in.range_count; j++) {
            AckRange rng;
            rng.gap = getRandomValidValue();
            rng.range = getRandomValidValue();
            _in.ranges.push_back(rng);
        }

        if (_in.type == 3) {
            EcnCount ecn_count;
            ecn_count.ect0 = getRandomValidValue();
            ecn_count.ect1 = getRandomValidValue();
            ecn_count.ecnce = getRandomValidValue();
            _in.ecn_count.emplace(ecn_count);
        }

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
        ASSERT_EQ(_in.largest_ack_num, _out.largest_ack_num);
        ASSERT_EQ(_in.delay, _out.delay);
        ASSERT_EQ(_in.range_count, _out.range_count);

        for (int j = 0; j < _in.range_count; j++) {
            ASSERT_EQ(_in.ranges[j].gap, _out.ranges[j].gap);
            ASSERT_EQ(_in.ranges[j].range, _out.ranges[j].range);
        }

        if (_in.type == 3) {
            ASSERT_EQ(_in.ecn_count.value().ect0, _out.ecn_count.value().ect0);
            ASSERT_EQ(_in.ecn_count.value().ect1, _out.ecn_count.value().ect1);
            ASSERT_EQ(_in.ecn_count.value().ecnce,
                      _out.ecn_count.value().ecnce);
        }
        delete[] out;
        out = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
