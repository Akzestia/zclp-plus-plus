#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(VariableLengthIntegerTest, EncodeDecodeCorrectness) {
    using namespace zclp_test_heplers;
    for (int i = 0; i < 100; i++) {
        uint64_t originalValue = getRandomValidValue();

        VariableLengthInteger vl(originalValue);
        uint8_t* encoded_buffer = new uint8_t[vl.byte_size()]();
        auto enc_res = zclp_encoding::encode_vl_integer(vl, encoded_buffer);
        if (!enc_res) {
            delete[] encoded_buffer;
            encoded_buffer = nullptr;
            FAIL();
        }
        VariableLengthInteger decodedVl;
        auto dec_res =
            zclp_encoding::decode_vl_integer(encoded_buffer, decodedVl);
        if (!dec_res) {
            delete[] encoded_buffer;
            encoded_buffer = nullptr;
            FAIL();
        }
        ASSERT_EQ(decodedVl(), vl());
        ASSERT_EQ(decodedVl.byte_size(), vl.byte_size());

        delete[] encoded_buffer;
        encoded_buffer = nullptr;
    }
}

TEST(VariableLengthIntegerTest, EdgeCaseValues) {
    std::vector<uint64_t> edge_cases = {
        0, 63, 64, 16383, 16384, 1073741823, 1073741824, 4611686018427387903};

    // 2743802114606235814
    // 4611686018427387903

    for (size_t i = 0; i < edge_cases.size(); i++) {
        uint64_t originalValue = edge_cases[i];

        VariableLengthInteger vl(originalValue);
        uint8_t* encodedData = new uint8_t[vl.byte_size()]();
        auto encodingResult = zclp_encoding::encode_vl_integer(vl, encodedData);

        VariableLengthInteger decodedVl;
        auto decodingResult =
            zclp_encoding::decode_vl_integer(encodedData, decodedVl);
        ASSERT_EQ(decodedVl(), vl()) << "Edge case failed for value: " << vl();
        ASSERT_EQ(decodedVl.byte_size(), vl.byte_size())
            << "Edge case length mismatch for value: " << vl.byte_size();

        delete[] encodedData;
        encodedData = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
