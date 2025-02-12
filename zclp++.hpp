#ifndef ZCLP_PLUS_PLUS
#define ZCLP_PLUS_PLUS

#include <memory.h>
#include <unistd.h>

#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <variant>
#include <vector>

/*
    https://www.ietf.org/archive/id/draft-mcquistin-quic-augmented-diagrams-05.html

    ///-\\\///-\\\///-\\\           ///-\\\///-\\\///-\\\
    \\\-///\\\-///\\\-///           \\\-///\\\-///\\\-///

    ///-\\\///-\\\///-\\\           ///-\\\///-\\\///-\\\
    \\\-///\\\-///\\\-///           \\\-///\\\-///\\\-///

    Bits	      Binary Mask	     Hex Mask	   Decimal Mask
    1-bit	      00000001	         0x01	       1
    2-bit	      00000011	         0x03	       3
    3-bit	      00000111	         0x07	       7
    4-bit	      00001111	         0x0F	       15
    5-bit	      00011111	         0x1F	       31
    6-bit	      00111111	         0x3F	       63
    7-bit	      01111111	         0x7F	       127
    8-bit	      11111111	         0xFF	       255
*/

template<class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};

template<class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

struct EncodingResult {
    bool success;
    size_t len;
};

struct VariableLengthInteger {
  private:
    uint8_t len : 2;
    uint64_t value;

  public:
    VariableLengthInteger() : len(0), value(0) {}

    explicit VariableLengthInteger(uint64_t val) { *this = val; }

    size_t byte_size() const { return pow(2, len); }

    VariableLengthInteger& operator=(uint64_t val) {
        uint8_t required_len;
        if (val <= 0x3F)
            required_len = 0;  // 6 bits (1 byte) 63
        else if (val <= 0x3FFF)
            required_len = 1;  // 14 bits (2 bytes) 16,383
        else if (val <= 0x3FFFFFFF)
            required_len = 2;  // 30 bits (4 bytes) 1,073,741,823
        else
            required_len = 3;  // 62 bits (8 bytes) 4,611,686,018,427,387,903

        uint64_t max_val = (1ULL << ((1 << required_len) * 8 - 2)) - 1;
        if (val > max_val) {
            throw "Way too big value";
        }
        len = required_len;
        value = val;
        return *this;
    }

    operator uint64_t() const { return value; }
    uint64_t operator()() const { return value; }
    uint8_t len_() const { return len; }
};

struct StatelessReset;
struct VersionNegotiation;
struct LongHeader;
struct ProtectedLongHeader;
struct Initial;
struct ZeroRTT;
struct HandShake;
struct Retry;
struct ShortHeader;

EncodingResult decode_vl_integer(uint8_t* in, VariableLengthInteger& out);

namespace Frames {
struct Padding {
    VariableLengthInteger type;  // 0
    size_t byte_size() const { return type.byte_size(); }
    static EncodingResult decode(uint8_t* in, Padding& out) {
        auto _ = decode_vl_integer(in, out.type);
        return {_.success, _.len};
    };
};

struct Ping {
    VariableLengthInteger type;  // 1
    size_t byte_size() const { return type.byte_size(); }

    static EncodingResult decode(uint8_t* in, Ping& out) {
        auto _ = decode_vl_integer(in, out.type);
        return {_.success, _.len};
    };
};

struct AckRange {
    VariableLengthInteger gap;    // 1
    VariableLengthInteger range;  // 1
    size_t byte_size() const { return gap.byte_size() + range.byte_size(); }

    static EncodingResult decode(uint8_t* in, AckRange& out) {
        size_t offset = 0;
        auto _ = decode_vl_integer(in, out.gap);
        if (!_.success)
            return {false, _.len};

        offset += _.len;
        uint8_t* range_ref = in + offset;
        auto __ = decode_vl_integer(range_ref, out.range);
        if (!__.success)
            return {false, __.len + offset};
        range_ref = nullptr;
        offset += __.len;

        return {true, offset};
    };
};

struct EcnCount {
    VariableLengthInteger ect0;
    VariableLengthInteger ect1;
    VariableLengthInteger ecnce;
    size_t byte_size() const {
        return ect0.byte_size() + ect1.byte_size() + ecnce.byte_size();
    }

    static EncodingResult decode(uint8_t* in, EcnCount& out) {
        size_t offset = 0;

        uint8_t* ect0_ref = in + offset;
        auto res = decode_vl_integer(ect0_ref, out.ect0);
        if (!res.success)
            return {false, res.len + offset};
        offset += res.len;
        ect0_ref = nullptr;

        uint8_t* ect1_ref = in + offset;
        auto res2 = decode_vl_integer(ect1_ref, out.ect1);
        if (!res2.success)
            return {false, res.len + offset};
        offset += res2.len;
        ect1_ref = nullptr;

        uint8_t* ecnce_ref = in + offset;
        auto res3 = decode_vl_integer(ecnce_ref, out.ecnce);
        if (!res3.success)
            return {false, res.len + offset};
        offset += res3.len;
        ecnce_ref = nullptr;
        return {true, offset};
    }
};

struct Ack {
    VariableLengthInteger type;  // 3 | 4
    VariableLengthInteger largest_ack_num;
    VariableLengthInteger delay;
    VariableLengthInteger range_count;
    std::vector<AckRange> ranges;
    std::optional<EcnCount> ecn_count;  // FT.Value == 3

    size_t byte_size() const {
        size_t ranges_size = 0;
        for (auto range : ranges)
            ranges_size += range.byte_size();

        if (ecn_count.has_value())
            ranges_size += ecn_count.value().byte_size();

        return type.byte_size() + largest_ack_num.byte_size()
            + delay.byte_size() + range_count.byte_size() + ranges_size;
    }

    static EncodingResult decode(uint8_t* in, Ack& out) {
        size_t offset = 0;
        auto FT_RES = decode_vl_integer(in, out.type);
        if (!FT_RES.success)
            return {false, FT_RES.len};
        offset += FT_RES.len;
        uint8_t* ref_lan = in + offset;
        auto vl_lan_res = decode_vl_integer(ref_lan, out.largest_ack_num);
        if (!vl_lan_res.success)
            return {false, vl_lan_res.len + offset};
        offset += vl_lan_res.len;
        ref_lan = nullptr;

        uint8_t* ref_delay = in + offset;
        auto vl_delay_res = decode_vl_integer(ref_delay, out.delay);
        if (!vl_delay_res.success)
            return {false, vl_lan_res.len + offset};
        offset += vl_delay_res.len;
        ref_delay = nullptr;

        uint8_t* ref_range_count = in + offset;
        auto vl_range_count_res =
            decode_vl_integer(ref_range_count, out.range_count);
        if (!vl_range_count_res.success)
            return {false, vl_lan_res.len + offset};
        offset += vl_range_count_res.len;
        ref_range_count = nullptr;

        uint8_t* ranges_ref = in + offset;
        for (int i = 0; i < out.range_count; i++) {
            AckRange ack_range_out;
            auto _ = AckRange::decode(ranges_ref, ack_range_out);
            if (!_.success)
                return {false, _.len + offset};
            out.ranges.push_back(ack_range_out);
            offset += _.len;
            ranges_ref = in + offset;
        }
        ranges_ref = nullptr;

        if (out.type == 3) {
            uint8_t* ecn_ref = in + offset;
            auto _ = EcnCount::decode(ecn_ref, out.ecn_count.value());
            if (!_.success)
                return {false, _.len + offset};
            ecn_ref = nullptr;
            offset += _.len;
        }

        return {true, offset};
    };
};

struct ResetStream {
    VariableLengthInteger type;  // 4
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;
    VariableLengthInteger final_size;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size() + error_code.byte_size()
            + final_size.byte_size();
    }
    static EncodingResult decode(uint8_t* in, ResetStream& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_stream_id = in + offset;

        auto stream_id_res = decode_vl_integer(ref_stream_id, out.stream_id);
        if (!stream_id_res.success)
            return {false, stream_id_res.len + offset};
        offset += stream_id_res.len;
        ref_stream_id = nullptr;

        uint8_t* ref_error_code = in + offset;

        auto error_code_res = decode_vl_integer(ref_error_code, out.error_code);
        if (!error_code_res.success)
            return {false, error_code_res.len + offset};
        offset += error_code_res.len;
        ref_error_code = nullptr;

        uint8_t* ref_final_size = in + offset;

        auto final_size_res = decode_vl_integer(ref_final_size, out.final_size);
        if (!final_size_res.success)
            return {false, final_size_res.len + offset};
        offset += final_size_res.len;
        ref_final_size = nullptr;

        return {true, offset};
    }
};

struct StopSending {
    VariableLengthInteger type;  // 5;
    VariableLengthInteger stream_id;
    VariableLengthInteger error_code;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size()
            + error_code.byte_size();
    }
    static EncodingResult decode(uint8_t* in, StopSending& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_stream_id = in + offset;

        auto stream_id_res = decode_vl_integer(ref_stream_id, out.stream_id);
        if (!stream_id_res.success)
            return {false, stream_id_res.len + offset};
        offset += stream_id_res.len;
        ref_stream_id = nullptr;

        uint8_t* ref_error_code = in + offset;

        auto error_code_res = decode_vl_integer(ref_error_code, out.error_code);
        if (!error_code_res.success)
            return {false, error_code_res.len + offset};
        offset += error_code_res.len;
        ref_error_code = nullptr;

        return {true, offset};
    }
};

struct Crypto {
    VariableLengthInteger type;  // 6;
    VariableLengthInteger offset;
    VariableLengthInteger length;
    uint8_t* data;

    size_t byte_size() const {
        return type.byte_size() + offset.byte_size() + length.byte_size()
            + length();
    }
    static EncodingResult decode(uint8_t* in, Crypto& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_offset = in + offset;

        auto offset_res = decode_vl_integer(ref_offset, out.offset);
        if (!offset_res.success)
            return {false, offset_res.len + offset};
        offset += offset_res.len;
        ref_offset = nullptr;

        uint8_t* ref_error_code = in + offset;

        auto length_res = decode_vl_integer(ref_error_code, out.length);
        if (!length_res.success)
            return {false, length_res.len + offset};
        offset += length_res.len;
        ref_error_code = nullptr;

        out.data = new uint8_t[out.length]();
        uint8_t* ref_data = in + offset;
        memcpy(out.data, ref_data, out.length);
        ref_data = nullptr;

        offset += out.length;
        return {true, offset};
    }
};

struct NewToken {
    VariableLengthInteger type;  // 7;
    VariableLengthInteger length;
    uint8_t* token;

    size_t byte_size() const {
        return type.byte_size() + length.byte_size() + length();
    }
    static EncodingResult decode(uint8_t* in, NewToken& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_length = in + offset;

        auto length_res = decode_vl_integer(ref_length, out.length);
        if (!length_res.success)
            return {false, length_res.len + offset};
        offset += length_res.len;
        ref_length = nullptr;

        out.token = new uint8_t[out.length]();
        uint8_t* ref_token = in + offset;
        memcpy(out.token, ref_token, out.length);
        ref_token = nullptr;

        offset += out.length;
        return {true, offset};
    }
};

struct Stream {
    uint8_t unused : 5;  // 1
    uint8_t off : 1;
    uint8_t len : 1;
    uint8_t fin : 1;

    VariableLengthInteger stream_id;
    VariableLengthInteger length;
    uint8_t* stream_data;

    size_t byte_size() const {
        return 1 + stream_id.byte_size() + length.byte_size() + length();
    }
    static EncodingResult decode(uint8_t* in, Stream& out);
};

struct MaxData {
    VariableLengthInteger type;  // 16
    VariableLengthInteger max_data;

    size_t byte_size() const { return type.byte_size() + max_data.byte_size(); }
    static EncodingResult decode(uint8_t* in, MaxData& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_max_data = in + offset;

        auto max_data_res = decode_vl_integer(ref_max_data, out.type);
        if (!max_data_res.success)
            return {false, max_data_res.len + offset};
        offset += max_data_res.len;
        ref_max_data = nullptr;

        return {true, offset};
    }
};

struct MaxStreamData {
    VariableLengthInteger type;  // 17
    VariableLengthInteger stream_id;
    VariableLengthInteger max_stream_data;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size()
            + max_stream_data.byte_size();
    }
    static EncodingResult decode(uint8_t* in, MaxStreamData& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_stream_id = in + offset;

        auto stream_id_res = decode_vl_integer(ref_stream_id, out.stream_id);
        if (!stream_id_res.success)
            return {false, stream_id_res.len + offset};
        offset += stream_id_res.len;
        ref_stream_id = nullptr;

        uint8_t* ref_max_stream_data = in + offset;

        auto max_stream_data_res =
            decode_vl_integer(ref_max_stream_data, out.max_stream_data);
        if (!max_stream_data_res.success)
            return {false, max_stream_data_res.len + offset};
        offset += max_stream_data_res.len;
        ref_max_stream_data = nullptr;

        return {true, offset};
    }
};

struct MaxStreams {
    VariableLengthInteger type;  // 18 || 19
    VariableLengthInteger max_streams;

    size_t byte_size() const {
        return type.byte_size() + max_streams.byte_size();
    }
    static EncodingResult decode(uint8_t* in, MaxStreams& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_max_streams = in + offset;

        auto max_streams_res =
            decode_vl_integer(ref_max_streams, out.max_streams);
        if (!max_streams_res.success)
            return {false, max_streams_res.len + offset};
        offset += max_streams_res.len;
        ref_max_streams = nullptr;

        return {true, offset};
    }
};

struct DataBlocked {
    VariableLengthInteger type;  // 20
    VariableLengthInteger data_limit;

    size_t byte_size() const {
        return type.byte_size() + data_limit.byte_size();
    }
    static EncodingResult decode(uint8_t* in, DataBlocked& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_data_limit = in + offset;

        auto data_limit_res = decode_vl_integer(ref_data_limit, out.data_limit);
        if (!data_limit_res.success)
            return {false, data_limit_res.len + offset};
        offset += data_limit_res.len;
        ref_data_limit = nullptr;

        return {true, offset};
    }
};

struct StreamDataBlocked {
    VariableLengthInteger type;  // 21
    VariableLengthInteger stream_id;
    VariableLengthInteger stream_data_limit;

    size_t byte_size() const {
        return type.byte_size() + stream_id.byte_size()
            + stream_data_limit.byte_size();
    }
    static EncodingResult decode(uint8_t* in, StreamDataBlocked& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_stream_id = in + offset;

        auto stream_id_res = decode_vl_integer(ref_stream_id, out.stream_id);
        if (!stream_id_res.success)
            return {false, stream_id_res.len + offset};
        offset += stream_id_res.len;
        ref_stream_id = nullptr;

        uint8_t* ref_stream_data_limit = in + offset;

        auto stream_data_limit_res =
            decode_vl_integer(ref_stream_data_limit, out.stream_data_limit);
        if (!stream_data_limit_res.success)
            return {false, stream_data_limit_res.len + offset};
        offset += stream_data_limit_res.len;
        ref_stream_data_limit = nullptr;

        return {true, offset};
    }
};

struct StreamsBlocked {
    VariableLengthInteger type;  // 22 || 23
    VariableLengthInteger stream_limit;

    size_t byte_size() const {
        return type.byte_size() + stream_limit.byte_size();
    }
    static EncodingResult decode(uint8_t* in, StreamsBlocked& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_stream_limit = in + offset;

        auto stream_limit_res =
            decode_vl_integer(ref_stream_limit, out.stream_limit);
        if (!stream_limit_res.success)
            return {false, stream_limit_res.len + offset};
        offset += stream_limit_res.len;
        ref_stream_limit = nullptr;

        return {true, offset};
    }
};

struct NewConnectionId {
    VariableLengthInteger type;  // 24
    VariableLengthInteger sequence_number;
    VariableLengthInteger retire_prior_to;
    uint32_t connection_id;
    uint8_t stateless_reset_token[16];

    size_t byte_size() const {
        return type.byte_size() + sequence_number.byte_size()
            + retire_prior_to.byte_size() + 4 + 16;
    }
    static EncodingResult decode(uint8_t* in, NewConnectionId& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_sequence_number = in + offset;

        auto sequence_number_res =
            decode_vl_integer(ref_sequence_number, out.sequence_number);
        if (!sequence_number_res.success)
            return {false, sequence_number_res.len + offset};
        offset += sequence_number_res.len;
        ref_sequence_number = nullptr;

        uint8_t* ref_retire_prior_to = in + offset;

        auto retire_prior_to_res =
            decode_vl_integer(ref_retire_prior_to, out.retire_prior_to);
        if (!retire_prior_to_res.success)
            return {false, retire_prior_to_res.len + offset};
        offset += retire_prior_to_res.len;
        ref_retire_prior_to = nullptr;

        uint8_t* ref_connection_id = in + offset;
        memcpy(&out.connection_id, ref_connection_id, 4);
        offset += 4;
        ref_connection_id = nullptr;

        uint8_t* ref_stateless_reset_token = in + offset;
        memcpy(&out.stateless_reset_token, ref_stateless_reset_token, 16);
        offset += 16;
        ref_stateless_reset_token = nullptr;

        return {true, offset};
    }
};

struct RetireConnectionId {
    VariableLengthInteger type;  // 25
    VariableLengthInteger sequence_number;

    size_t byte_size() const {
        return type.byte_size() + sequence_number.byte_size();
    }
    static EncodingResult decode(uint8_t* in, RetireConnectionId& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_sequence_number = in + offset;

        auto sequence_number_res =
            decode_vl_integer(ref_sequence_number, out.sequence_number);
        if (!sequence_number_res.success)
            return {false, sequence_number_res.len + offset};
        offset += sequence_number_res.len;
        ref_sequence_number = nullptr;

        return {true, offset};
    }
};

struct PathChallange {
    VariableLengthInteger type;  // 26
    uint64_t data;

    size_t byte_size() const { return type.byte_size() + 8; }
    static EncodingResult decode(uint8_t* in, PathChallange& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_data = in + offset;

        memcpy(&out.data, ref_data, 8);

        return {true, offset};
    }
};

struct PathResponse {
    VariableLengthInteger type;  // 27
    uint64_t data;

    size_t byte_size() const { return type.byte_size() + 8; }
    static EncodingResult decode(uint8_t* in, PathResponse& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_data = in + offset;

        memcpy(&out.data, ref_data, 8);

        return {true, offset};
    }
};

struct ConnectionClose {
    VariableLengthInteger type;  // 28 || 29
    VariableLengthInteger error;
    VariableLengthInteger frame_type;
    VariableLengthInteger phrase_len;
    uint8_t* phrase;

    size_t byte_size() const {
        return type.byte_size() + error.byte_size() + frame_type.byte_size()
            + phrase_len.byte_size();
    }
    static EncodingResult decode(uint8_t* in, ConnectionClose& out) {
        size_t offset = 0;

        uint8_t* ref_type = in + offset;

        auto type_res = decode_vl_integer(ref_type, out.type);
        if (!type_res.success)
            return {false, type_res.len + offset};
        offset += type_res.len;
        ref_type = nullptr;

        uint8_t* ref_error = in + offset;

        auto error_res = decode_vl_integer(ref_error, out.error);
        if (!error_res.success)
            return {false, error_res.len + offset};
        offset += error_res.len;
        ref_error = nullptr;

        uint8_t* ref_frame_type = in + offset;

        auto frame_type_res = decode_vl_integer(ref_type, out.frame_type);
        if (!frame_type_res.success)
            return {false, frame_type_res.len + offset};
        offset += frame_type_res.len;
        ref_frame_type = nullptr;

        uint8_t* ref_phrase_len = in + offset;

        auto phrase_len_res = decode_vl_integer(ref_type, out.phrase_len);
        if (!phrase_len_res.success)
            return {false, phrase_len_res.len + offset};
        offset += phrase_len_res.len;
        ref_phrase_len = nullptr;

        uint8_t* ref_phrase = in + offset;
        out.phrase = new uint8_t[out.phrase_len]();
        memcpy(out.phrase, ref_phrase, out.phrase_len);
        offset += out.phrase_len;

        return {true, offset};
    }
};

struct HandShakeDone {
    VariableLengthInteger type;  // 30

    size_t byte_size() const { return type.byte_size(); }
    static EncodingResult decode(uint8_t* in, HandShakeDone& out) {
        auto type_res = decode_vl_integer(in, out.type);
        return {type_res.success, type_res.len};
    }
};

using FrameVariant =
    std::variant<Padding, Ping, Ack, ResetStream, StopSending, Crypto, NewToken,
                 Stream, MaxData, MaxStreamData, MaxStreams, DataBlocked,
                 StreamDataBlocked, StreamsBlocked, NewConnectionId,
                 RetireConnectionId, PathChallange, PathResponse,
                 ConnectionClose, HandShakeDone>;

inline size_t frame_size(const Frames::FrameVariant frame) {
    return std::visit(
        overloaded{
            [](const Frames::Padding& f) -> size_t { return f.byte_size(); },
            [](const Frames::Ping& f) -> size_t { return f.byte_size(); },
            [](const Frames::Ack& f) -> size_t { return f.byte_size(); },
            [](const Frames::ResetStream& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::StopSending& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::Crypto& f) -> size_t { return f.byte_size(); },
            [](const Frames::NewToken& f) -> size_t { return f.byte_size(); },
            [](const Frames::Stream& f) -> size_t { return f.byte_size(); },
            [](const Frames::MaxData& f) -> size_t { return f.byte_size(); },
            [](const Frames::MaxStreamData& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::MaxStreams& f) -> size_t { return f.byte_size(); },
            [](const Frames::DataBlocked& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::StreamDataBlocked& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::StreamsBlocked& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::NewConnectionId& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::RetireConnectionId& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::PathChallange& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::PathResponse& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::ConnectionClose& f) -> size_t {
                return f.byte_size();
            },
            [](const Frames::HandShakeDone& f) -> size_t {
                return f.byte_size();
            }},
        frame);
}

inline size_t frame_payload_size(std::vector<FrameVariant> payload) {
    size_t size = 0;
    for (auto x : payload)
        size += frame_size(x);
    return size;
}

inline FrameVariant* get_frame_type(uint8_t* in, size_t len) {
    VariableLengthInteger FT;
    auto FT_RES = decode_vl_integer(in, FT);
    if (!FT_RES.success)
        return nullptr;
    switch (FT) {
        /*
            Each Frame has it's own ::decode(), method which is responsible for
            decoding frame from raw bytes.
        */
    case 0: {
        Padding out;
        if (!Padding::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 1: {
        Ping out;
        if (!Ping::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 2:
    case 3: {
        Ack out;
        if (!Ack::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 4: {
        ResetStream out;
        if (!ResetStream::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 5: {
        StopSending out;
        if (!StopSending::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 6: {
        Crypto out;
        if (!Crypto::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 7: {
        NewToken out;
        if (!NewToken::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 16: {
        MaxData out;
        if (!MaxData::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 17: {
        MaxStreamData out;
        if (!MaxStreamData::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 18:
    case 19: {
        MaxStreams out;
        if (!MaxStreams::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 20: {
        DataBlocked out;
        if (!DataBlocked::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 21: {
        StreamDataBlocked out;
        if (!StreamDataBlocked::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 22:
    case 23: {
        StreamsBlocked out;
        if (!StreamsBlocked::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 24: {
        NewConnectionId out;
        if (!NewConnectionId::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 25: {
        RetireConnectionId out;
        if (!RetireConnectionId::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 26: {
        PathChallange out;
        if (!PathChallange::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;
    case 27: {
        PathResponse out;
        if (!PathResponse::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 28:
    case 29: {
        ConnectionClose out;
        if (!ConnectionClose::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    case 30: {
        HandShakeDone out;
        if (!HandShakeDone::decode(in, out).success)
            return nullptr;
        return new FrameVariant(out);
    } break;

    // Stream Frames
    default: {
        Stream out;
        return new FrameVariant(out);
    }
    };
}
}  // namespace Frames

namespace Packets {

struct StatelessReset {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;

    VariableLengthInteger unpredictable_bits;
    uint8_t reset_token[16];

    size_t byte_size() const {
        /*
            16 bytes token
            1 byte HF && FBs
            N bytes unpredictable_bits.size()
        */
        return 16 + 1 + unpredictable_bits.byte_size();
    }
};

struct VersionNegotiation {
    uint8_t header_form : 1;
    uint8_t unused : 6;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;
    std::vector<uint32_t> supported_versions;

    size_t byte_size() const {
        /*
            1 byte HF && unused
            12 bytes version_id && destination_connection_id &&
            source_connection_id
            4 * N bytes supported_versions
        */
        return 13 + 4 * supported_versions.size();
    }
};

struct LongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t reserved_bits : 2;
    uint8_t packet_number_length : 2;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;

    size_t byte_size() const {
        /*
            1 byte - ..version_id
            12 bytes version_id + destination_connection_id +
           source_connection_id
        */
        return 13;
    }
};

struct ProtectedLongHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t packet_type : 2;
    uint8_t protected_bits : 4;
    uint32_t version_id;
    uint32_t destination_connection_id;
    uint32_t source_connection_id;

    size_t byte_size() const {
        /*
            1 byte - ..version_id
            12 bytes version_id + destination_connection_id +
           source_connection_id
        */
        return 13;
    }
};

struct Initial {
    LongHeader header;

    // token length in bytes token_length()
    VariableLengthInteger token_length;
    uint8_t* token;

    // The length of the remainder of the packet in bytes length()
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const {
        return header.byte_size() + token_length() + length();
    }
};

struct ZeroRTT {
    LongHeader header;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const { return header.byte_size() + length(); }
};

struct HandShake {
    LongHeader header;
    VariableLengthInteger length;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const { return header.byte_size() + length(); }
};

struct Retry {
    LongHeader header;
    uint8_t* token;
    uint8_t integrity_tag[16];

    size_t byte_size() const {
        /*
            token len external
            ||
            Retry packet size - header - integrity_tag size
        */
        return header.byte_size() + 16;
    }
};

struct ShortHeader {
    uint8_t header_form : 1;
    uint8_t fixed_bit : 1;
    uint8_t spin_bit : 1;
    uint8_t reserved_bits : 2;
    uint8_t key_phase : 1;
    uint8_t packet_number_length : 2;
    uint32_t destination_connection;
    uint8_t packet_number : 3;
    std::vector<Frames::FrameVariant> payload;  // Frames

    size_t byte_size() const {
        /*

        */
        return 2 + 4 + Frames::frame_payload_size(payload);
    }
};

}  // namespace Packets

namespace Structs {

enum C_Type : uint8_t {
    authentication = 0,
    client_request = 1,
    p2p = 2,
};

struct Connection {
    uint32_t id;
    C_Type type;
    uint32_t params;
    std::atomic<bool> alive;
};
}  // namespace Structs

#endif  // ZCLP_PLUS_PLUS
