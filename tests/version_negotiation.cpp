#include <gtest/gtest.h>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(VersionNegotiationTest, EncodeDecode) {
    using namespace Packets;
    using namespace zclp_test_heplers;

    for (int i = 0; i < 1000000; i++) {
        Packets::VersionNegotiation vn;
        vn.header_form = getRandomBit();
        vn.unused = getRandomBit() & 0x3F;  // Ensure it's a 6-bit value
        vn.version_id = getRandomVersionID();
        vn.destination_connection_id = getRandomConnectionID();
        vn.source_connection_id = getRandomConnectionID();
        vn.supported_versions = getRandomSupportedVersions(3);

        uint8_t* encoded_buffer = nullptr;
        auto enc_res =
            zclp_encoding::encode_version_negotiation(vn, encoded_buffer);
        if (!enc_res) {
            delete[] encoded_buffer;
            encoded_buffer = nullptr;
            FAIL();
        }
        ASSERT_TRUE(enc_res.success);
        ASSERT_GT(enc_res.len, 0u);

        Packets::VersionNegotiation vn_decoded;
        auto dec_res = zclp_encoding::decode_version_negotiation(
            encoded_buffer, enc_res.len, vn_decoded);
        if (!dec_res) {
            delete[] encoded_buffer;
            encoded_buffer = nullptr;
            FAIL();
        }
        ASSERT_TRUE(dec_res.success);

        ASSERT_EQ(vn.header_form, vn_decoded.header_form);
        ASSERT_EQ(vn.unused, vn_decoded.unused);
        ASSERT_EQ(vn.version_id, vn_decoded.version_id);
        ASSERT_EQ(vn.destination_connection_id,
                  vn_decoded.destination_connection_id);
        ASSERT_EQ(vn.source_connection_id, vn_decoded.source_connection_id);
        ASSERT_EQ(vn.supported_versions.size(),
                  vn_decoded.supported_versions.size());

        for (size_t j = 0; j < vn.supported_versions.size(); ++j) {
            ASSERT_EQ(vn.supported_versions[j],
                      vn_decoded.supported_versions[j]);
        }

        delete[] encoded_buffer;
        encoded_buffer = nullptr;
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
