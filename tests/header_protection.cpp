#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "../zclp++/zclp++.h"
#include "../zclp_utils/zclp_utils.h"

TEST(ShortHeaderTest, ProtectionApplyRemove) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    for (int i = 0; i < 1000000; i++) {
        Packets::ShortHeader sh;
        sh.header_form = 0;
        sh.fixed_bit = 1;
        sh.spin_bit = 0;
        sh.reserved_bits = 0;
        sh.key_phase = 1;
        sh.packet_number_length = getRandomPacketNumberLength();
        sh.destination_connection = getRandomConnectionID();
        sh.packet_number = getRandomPacketNumber();

        std::vector<uint8_t> sample = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                       0xba, 0xbe, 0x00, 0x11, 0x22, 0x33,
                                       0x44, 0x55, 0x66, 0x77};

        std::array<uint8_t, 16> hp_key = {0x1f, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f,
                                          0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5,
                                          0xd6, 0xe7, 0xf8, 0x09};

        Packets::ShortHeader sh_original = sh;

        std::vector<uint8_t> short_header_protected(
            sizeof(Packets::ShortHeader));
        std::memcpy(short_header_protected.data(), &sh,
                    sizeof(Packets::ShortHeader));
        bool res_a = zclp_tls::apply_header_protection(short_header_protected,
                                                       sample, hp_key);
        ASSERT_EQ(res_a, true);
        std::vector<uint8_t> short_header_restored = short_header_protected;
        bool res_r = zclp_tls::remove_header_protection(short_header_restored,
                                                        sample, hp_key);
        ASSERT_EQ(res_r, true);
        Packets::ShortHeader sh_restored;
        std::memcpy(&sh_restored, short_header_restored.data(),
                    sizeof(Packets::ShortHeader));

        ASSERT_EQ(sh_original.header_form, sh_restored.header_form);
        ASSERT_EQ(sh_original.fixed_bit, sh_restored.fixed_bit);
        ASSERT_EQ(sh_original.spin_bit, sh_restored.spin_bit);
        ASSERT_EQ(sh_original.reserved_bits, sh_restored.reserved_bits);
        ASSERT_EQ(sh_original.key_phase, sh_restored.key_phase);
        ASSERT_EQ(sh_original.packet_number_length,
                  sh_restored.packet_number_length);
        ASSERT_EQ(sh_original.destination_connection,
                  sh_restored.destination_connection);
        ASSERT_EQ(sh_original.packet_number, sh_restored.packet_number);
    }
}

TEST(LongHeaderTest, ProtectionApplyRemove) {
    using namespace Packets;
    using namespace zclp_test_heplers;
    for (int i = 0; i < 1000000; i++) {
        Packets::LongHeader lh;
        lh.header_form = 1;
        lh.fixed_bit = 1;
        lh.packet_type = getRandomPacketNumber();
        lh.reserved_bits = 0;
        lh.packet_number_length = getRandomPacketNumberLength();
        lh.version_id = getRandomPacketNumber();
        lh.destination_connection_id = getRandomConnectionID();
        lh.source_connection_id = getRandomConnectionID();

        std::vector<uint8_t> sample = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                       0xba, 0xbe, 0x00, 0x11, 0x22, 0x33,
                                       0x44, 0x55, 0x66, 0x77};

        std::array<uint8_t, 16> hp_key = {0x1f, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f,
                                          0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5,
                                          0xd6, 0xe7, 0xf8, 0x09};

        Packets::LongHeader lh_original = lh;
        std::vector<uint8_t> long_header_protected(sizeof(Packets::LongHeader));
        std::memcpy(long_header_protected.data(), &lh,
                    sizeof(Packets::LongHeader));
        bool res_a = zclp_tls::apply_header_protection(long_header_protected,
                                                       sample, hp_key);
        ASSERT_EQ(res_a, true);
        std::vector<uint8_t> long_header_restored = long_header_protected;
        bool res_r = zclp_tls::remove_header_protection(long_header_restored,
                                                        sample, hp_key);
        ASSERT_EQ(res_r, true);
        Packets::LongHeader lh_restored;
        std::memcpy(&lh_restored, long_header_restored.data(),
                    sizeof(Packets::LongHeader));

        ASSERT_EQ(lh_original.header_form, lh_restored.header_form);
        ASSERT_EQ(lh_original.fixed_bit, lh_restored.fixed_bit);
        ASSERT_EQ(lh_original.packet_type, lh_restored.packet_type);
        ASSERT_EQ(lh_original.reserved_bits, lh_restored.reserved_bits);
        ASSERT_EQ(lh_original.packet_number_length,
                  lh_restored.packet_number_length);
        ASSERT_EQ(lh_original.version_id, lh_restored.version_id);
        ASSERT_EQ(lh_original.destination_connection_id,
                  lh_restored.destination_connection_id);
        ASSERT_EQ(lh_original.source_connection_id,
                  lh_restored.source_connection_id);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
