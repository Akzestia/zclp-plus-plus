#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "zclp++.h"

VariableLengthInteger::VariableLengthInteger() : len(0), value(0) {
}

VariableLengthInteger::VariableLengthInteger(uint64_t val) {
    *this = val;
}

size_t VariableLengthInteger::byte_size() const {
    return pow(2, len);
}

VariableLengthInteger& VariableLengthInteger::operator=(uint64_t val) {
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

namespace zclp_encoding {
EncodingResult decode_vl_integer(uint8_t* in, VariableLengthInteger& out);
EncodingResult encode_vl_integer(const VariableLengthInteger& in,
                                 uint8_t*& out);
}  // namespace zclp_encoding

namespace Frames {

size_t Padding::byte_size() const {
    return type.byte_size();
}

EncodingResult decode(uint8_t* in, Padding& out) {
    auto _ = zclp_encoding::decode_vl_integer(in, out.type);
    return {_, _.len};
};

EncodingResult encode(const Padding& in, uint8_t*& out) {
    auto d_type = zclp_encoding::encode_vl_integer(in.type, out);
    return {d_type, d_type.len};
}

size_t Ping::byte_size() const {
    return type.byte_size();
}

EncodingResult decode(uint8_t* in, Ping& out) {
    auto _ = zclp_encoding::decode_vl_integer(in, out.type);
    return {_, _.len};
};

EncodingResult encode(const Ping& in, uint8_t*& out) {
    auto d_type = zclp_encoding::encode_vl_integer(in.type, out);
    return {d_type, d_type.len};
}

size_t AckRange::byte_size() const {
    return gap.byte_size() + range.byte_size();
}

EncodingResult decode(uint8_t* in, AckRange& out) {
    size_t offset = 0;
    auto _ = zclp_encoding::decode_vl_integer(in, out.gap);
    if (!_)
        return {false, _.len};

    offset += _.len;
    uint8_t* range_ref = in + offset;
    auto __ = zclp_encoding::decode_vl_integer(range_ref, out.range);
    if (!__) {
        range_ref = nullptr;
        return {false, __.len + offset};
    }
    range_ref = nullptr;
    offset += __.len;

    return {true, offset};
};

EncodingResult encode(const AckRange& in, uint8_t*& out) {
    size_t offset = 0;

    uint8_t* d_gap_ref = out + offset;
    auto d_gap = zclp_encoding::encode_vl_integer(in.gap, d_gap_ref);
    if (!d_gap) {
        d_gap_ref = nullptr;
        return {d_gap, d_gap.len};
    }
    offset += d_gap.len;
    d_gap_ref = nullptr;

    uint8_t* d_range_ref = out + offset;
    auto d_range = zclp_encoding::encode_vl_integer(in.range, d_range_ref);
    if (!d_range) {
        d_range_ref = nullptr;
        return {d_range, d_range.len};
    }
    offset += d_range.len;
    d_range_ref = nullptr;

    return {true, offset};
}

size_t EcnCount::byte_size() const {
    return ect0.byte_size() + ect1.byte_size() + ecnce.byte_size();
}

EncodingResult decode(uint8_t* in, EcnCount& out) {
    size_t offset = 0;

    uint8_t* ect0_ref = in + offset;
    auto res = zclp_encoding::decode_vl_integer(ect0_ref, out.ect0);
    if (!res) {
        ect0_ref = nullptr;
        return {false, res.len + offset};
    }
    offset += res.len;
    ect0_ref = nullptr;

    uint8_t* ect1_ref = in + offset;
    auto res2 = zclp_encoding::decode_vl_integer(ect1_ref, out.ect1);
    if (!res2) {
        ect1_ref = nullptr;
        return {false, res.len + offset};
    }
    offset += res2.len;
    ect1_ref = nullptr;

    uint8_t* ecnce_ref = in + offset;
    auto res3 = zclp_encoding::decode_vl_integer(ecnce_ref, out.ecnce);
    if (!res3) {
        ecnce_ref = nullptr;
        return {false, res.len + offset};
    }
    offset += res3.len;
    ecnce_ref = nullptr;
    return {true, offset};
}

EncodingResult encode(const EcnCount& in, uint8_t*& out) {
    size_t offset = 0;

    uint8_t* d_ect0_ref = out + offset;
    auto d_ect0 = zclp_encoding::encode_vl_integer(in.ect0, d_ect0_ref);
    if (!d_ect0) {
        d_ect0_ref = nullptr;
        return {d_ect0, d_ect0.len};
    }
    offset += d_ect0.len;
    d_ect0_ref = nullptr;

    uint8_t* d_ect1_ref = out + offset;
    auto d_ect1 = zclp_encoding::encode_vl_integer(in.ect1, d_ect1_ref);
    if (!d_ect1) {
        d_ect1_ref = nullptr;
        return {d_ect1, d_ect1.len};
    }
    offset += d_ect1.len;
    d_ect1_ref = nullptr;

    uint8_t* d_ecnce_ref = out + offset;
    auto d_ecnce = zclp_encoding::encode_vl_integer(in.ecnce, d_ecnce_ref);
    if (!d_ecnce) {
        d_ecnce_ref = nullptr;
        return {d_ecnce, d_ecnce.len};
    }
    offset += d_ecnce.len;
    d_ecnce_ref = nullptr;

    return {true, offset};
}

size_t Ack::byte_size() const {
    size_t ranges_size = 0;
    for (auto range : ranges)
        ranges_size += range.byte_size();

    if (ecn_count.has_value())
        ranges_size += ecn_count.value().byte_size();

    return type.byte_size() + largest_ack_num.byte_size() + delay.byte_size()
        + range_count.byte_size() + ranges_size;
}

EncodingResult decode(uint8_t* in, Ack& out) {
    size_t offset = 0;
    auto FT_RES = zclp_encoding::decode_vl_integer(in, out.type);
    if (!FT_RES)
        return {false, FT_RES.len};
    offset += FT_RES.len;
    uint8_t* ref_lan = in + offset;
    auto vl_lan_res =
        zclp_encoding::decode_vl_integer(ref_lan, out.largest_ack_num);
    if (!vl_lan_res) {
        ref_lan = nullptr;
        return {false, vl_lan_res.len + offset};
    }
    offset += vl_lan_res.len;
    ref_lan = nullptr;

    uint8_t* ref_delay = in + offset;
    auto vl_delay_res = zclp_encoding::decode_vl_integer(ref_delay, out.delay);
    if (!vl_delay_res) {
        ref_delay = nullptr;
        return {false, vl_lan_res.len + offset};
    }
    offset += vl_delay_res.len;
    ref_delay = nullptr;

    uint8_t* ref_range_count = in + offset;
    auto vl_range_count_res =
        zclp_encoding::decode_vl_integer(ref_range_count, out.range_count);
    if (!vl_range_count_res) {
        ref_range_count = nullptr;
        return {false, vl_lan_res.len + offset};
    }
    offset += vl_range_count_res.len;
    ref_range_count = nullptr;

    uint8_t* ranges_ref = in + offset;
    for (int i = 0; i < out.range_count; i++) {
        AckRange ack_range_out;
        auto _ = decode(ranges_ref, ack_range_out);
        if (!_) {
            ranges_ref = nullptr;
            return {false, _.len + offset};
        }
        out.ranges.push_back(ack_range_out);
        offset += _.len;
        ranges_ref = in + offset;
    }
    ranges_ref = nullptr;

    if (out.type == 3) {
        uint8_t* ecn_ref = in + offset;
        auto _ = decode(ecn_ref, out.ecn_count.value());
        if (!_) {
            ecn_ref = nullptr;
            return {false, _.len + offset};
        }
        ecn_ref = nullptr;
        offset += _.len;
    }

    return {true, offset};
};

EncodingResult encode(const Ack& in, uint8_t*& out) {
    size_t offset = 0;

    uint8_t* d_type_ref = out + offset;
    auto d_type = zclp_encoding::encode_vl_integer(in.type, d_type_ref);
    if (!d_type) {
        d_type_ref = nullptr;
        return {d_type, d_type.len};
    }
    offset += d_type.len;
    d_type_ref = nullptr;

    uint8_t* d_largest_ack_num_ref = out + offset;
    auto d_largest_ack_num = zclp_encoding::encode_vl_integer(
        in.largest_ack_num, d_largest_ack_num_ref);
    if (!d_largest_ack_num) {
        d_largest_ack_num_ref = nullptr;
        return {d_largest_ack_num, d_largest_ack_num.len};
    }
    offset += d_largest_ack_num.len;
    d_largest_ack_num_ref = nullptr;

    uint8_t* d_delay_ref = out + offset;
    auto d_delay = zclp_encoding::encode_vl_integer(in.delay, d_delay_ref);
    if (!d_delay) {
        d_delay_ref = nullptr;
        return {d_delay, d_delay.len};
    }
    offset += d_delay.len;
    d_delay_ref = nullptr;

    uint8_t* d_range_count_ref = out + offset;
    auto d_range_count =
        zclp_encoding::encode_vl_integer(in.range_count, d_range_count_ref);
    if (!d_range_count) {
        d_range_count_ref = nullptr;
        return {d_range_count, d_range_count.len};
    }
    offset += d_range_count.len;
    d_range_count_ref = nullptr;

    for (const auto& range : in.ranges) {
        uint8_t* d_range_ref = out + offset;
        auto d_range =
            zclp_encoding::encode_vl_integer(in.range_count, d_range_ref);
        if (!d_range) {
            d_range_ref = nullptr;
            return {d_range, d_range.len};
        }
        offset += d_range.len;
        d_range_ref = nullptr;
    }

    if (in.ecn_count.has_value()) {
        uint8_t* ecn_count_ref = out + offset;
        auto d_ecn_count = encode(in.ecn_count.value(), ecn_count_ref);
        if (!d_ecn_count) {
            ecn_count_ref = nullptr;
            return {d_ecn_count, d_ecn_count.len};
        }
        ecn_count_ref = nullptr;
    }

    return {true, offset};
}

size_t ResetStream::byte_size() const {
    return type.byte_size() + stream_id.byte_size() + error_code.byte_size()
        + final_size.byte_size();
}
EncodingResult decode(uint8_t* in, ResetStream& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_stream_id = in + offset;

    auto stream_id_res =
        zclp_encoding::decode_vl_integer(ref_stream_id, out.stream_id);
    if (!stream_id_res) {
        ref_stream_id = nullptr;
        return {false, stream_id_res.len + offset};
    }
    offset += stream_id_res.len;
    ref_stream_id = nullptr;

    uint8_t* ref_error_code = in + offset;

    auto error_code_res =
        zclp_encoding::decode_vl_integer(ref_error_code, out.error_code);
    if (!error_code_res) {
        ref_error_code = nullptr;
        return {false, error_code_res.len + offset};
    }
    offset += error_code_res.len;
    ref_error_code = nullptr;

    uint8_t* ref_final_size = in + offset;

    auto final_size_res =
        zclp_encoding::decode_vl_integer(ref_final_size, out.final_size);
    if (!final_size_res) {
        ref_final_size = nullptr;
        return {false, final_size_res.len + offset};
    }
    offset += final_size_res.len;
    ref_final_size = nullptr;

    return {true, offset};
}

EncodingResult encode(const ResetStream& in, uint8_t*& out) {
}

size_t StopSending::byte_size() const {
    return type.byte_size() + stream_id.byte_size() + error_code.byte_size();
}
EncodingResult decode(uint8_t* in, StopSending& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_stream_id = in + offset;

    auto stream_id_res =
        zclp_encoding::decode_vl_integer(ref_stream_id, out.stream_id);
    if (!stream_id_res) {
        ref_stream_id = nullptr;
        return {false, stream_id_res.len + offset};
    }
    offset += stream_id_res.len;
    ref_stream_id = nullptr;

    uint8_t* ref_error_code = in + offset;

    auto error_code_res =
        zclp_encoding::decode_vl_integer(ref_error_code, out.error_code);
    if (!error_code_res) {
        ref_error_code = nullptr;
        return {false, error_code_res.len + offset};
    }
    offset += error_code_res.len;
    ref_error_code = nullptr;

    return {true, offset};
}

EncodingResult encode(const StopSending& in, uint8_t*& out) {
}

size_t Crypto::byte_size() const {
    return type.byte_size() + offset.byte_size() + length.byte_size()
        + length();
}
EncodingResult decode(uint8_t* in, Crypto& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_offset = in + offset;

    auto offset_res = zclp_encoding::decode_vl_integer(ref_offset, out.offset);
    if (!offset_res) {
        ref_offset = nullptr;
        return {false, offset_res.len + offset};
    }
    offset += offset_res.len;
    ref_offset = nullptr;

    uint8_t* ref_error_code = in + offset;

    auto length_res =
        zclp_encoding::decode_vl_integer(ref_error_code, out.length);
    if (!length_res) {
        ref_error_code = nullptr;
        return {false, length_res.len + offset};
    }
    offset += length_res.len;
    ref_error_code = nullptr;

    out.data = new uint8_t[out.length]();
    uint8_t* ref_data = in + offset;
    memcpy(out.data, ref_data, out.length);
    ref_data = nullptr;

    offset += out.length;
    return {true, offset};
}

EncodingResult encode(const Crypto& in, uint8_t*& out) {
}

size_t NewToken::byte_size() const {
    return type.byte_size() + length.byte_size() + length();
}

EncodingResult decode(uint8_t* in, NewToken& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_length = in + offset;

    auto length_res = zclp_encoding::decode_vl_integer(ref_length, out.length);
    if (!length_res) {
        ref_length = nullptr;
        return {false, length_res.len + offset};
    }
    offset += length_res.len;
    ref_length = nullptr;

    out.token = new uint8_t[out.length]();
    uint8_t* ref_token = in + offset;
    memcpy(out.token, ref_token, out.length);
    ref_token = nullptr;

    offset += out.length;
    return {true, offset};
}

EncodingResult encode(const NewToken& in, uint8_t*& out) {
}

size_t Stream::byte_size() const {
    return 1 + stream_id.byte_size() + length.byte_size() + length();
}
EncodingResult decode(uint8_t* in, Stream& out) {
}

EncodingResult encode(const Stream& in, uint8_t*& out) {
}

size_t MaxData::byte_size() const {
    return type.byte_size() + max_data.byte_size();
}
EncodingResult decode(uint8_t* in, MaxData& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_max_data = in + offset;

    auto max_data_res =
        zclp_encoding::decode_vl_integer(ref_max_data, out.type);
    if (!max_data_res) {
        ref_max_data = nullptr;
        return {false, max_data_res.len + offset};
    }
    offset += max_data_res.len;
    ref_max_data = nullptr;

    return {true, offset};
}

EncodingResult encode(const MaxData& in, uint8_t*& out) {
}

size_t MaxStreamData::byte_size() const {
    return type.byte_size() + stream_id.byte_size()
        + max_stream_data.byte_size();
}
EncodingResult decode(uint8_t* in, MaxStreamData& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_stream_id = in + offset;

    auto stream_id_res =
        zclp_encoding::decode_vl_integer(ref_stream_id, out.stream_id);
    if (!stream_id_res)
        return {false, stream_id_res.len + offset};
    offset += stream_id_res.len;
    ref_stream_id = nullptr;

    uint8_t* ref_max_stream_data = in + offset;

    auto max_stream_data_res = zclp_encoding::decode_vl_integer(
        ref_max_stream_data, out.max_stream_data);
    if (!max_stream_data_res) {
        ref_max_stream_data = nullptr;
        return {false, max_stream_data_res.len + offset};
    }
    offset += max_stream_data_res.len;
    ref_max_stream_data = nullptr;

    return {true, offset};
}

EncodingResult encode(const MaxStreamData& in, uint8_t*& out) {
}

size_t MaxStreams::byte_size() const {
    return type.byte_size() + max_streams.byte_size();
}
EncodingResult decode(uint8_t* in, MaxStreams& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_max_streams = in + offset;

    auto max_streams_res =
        zclp_encoding::decode_vl_integer(ref_max_streams, out.max_streams);
    if (!max_streams_res) {
        ref_max_streams = nullptr;
        return {false, max_streams_res.len + offset};
    }
    offset += max_streams_res.len;
    ref_max_streams = nullptr;

    return {true, offset};
}

EncodingResult encode(const MaxStreams& in, uint8_t*& out) {
}

size_t DataBlocked::byte_size() const {
    return type.byte_size() + data_limit.byte_size();
}
EncodingResult decode(uint8_t* in, DataBlocked& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_data_limit = in + offset;

    auto data_limit_res =
        zclp_encoding::decode_vl_integer(ref_data_limit, out.data_limit);
    if (!data_limit_res) {
        ref_data_limit = nullptr;
        return {false, data_limit_res.len + offset};
    }
    offset += data_limit_res.len;
    ref_data_limit = nullptr;

    return {true, offset};
}

EncodingResult encode(const DataBlocked& in, uint8_t*& out) {
}

size_t StreamDataBlocked::byte_size() const {
    return type.byte_size() + stream_id.byte_size()
        + stream_data_limit.byte_size();
}
EncodingResult decode(uint8_t* in, StreamDataBlocked& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_stream_id = in + offset;

    auto stream_id_res =
        zclp_encoding::decode_vl_integer(ref_stream_id, out.stream_id);
    if (!stream_id_res) {
        ref_stream_id = nullptr;
        return {false, stream_id_res.len + offset};
    }
    offset += stream_id_res.len;
    ref_stream_id = nullptr;

    uint8_t* ref_stream_data_limit = in + offset;

    auto stream_data_limit_res = zclp_encoding::decode_vl_integer(
        ref_stream_data_limit, out.stream_data_limit);
    if (!stream_data_limit_res) {
        ref_stream_data_limit = nullptr;
        return {false, stream_data_limit_res.len + offset};
    }
    offset += stream_data_limit_res.len;
    ref_stream_data_limit = nullptr;

    return {true, offset};
}

EncodingResult encode(const StreamDataBlocked& in, uint8_t*& out) {
}

size_t StreamsBlocked::byte_size() const {
    return type.byte_size() + stream_limit.byte_size();
}
EncodingResult decode(uint8_t* in, StreamsBlocked& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_stream_limit = in + offset;

    auto stream_limit_res =
        zclp_encoding::decode_vl_integer(ref_stream_limit, out.stream_limit);
    if (!stream_limit_res) {
        ref_stream_limit = nullptr;
        return {false, stream_limit_res.len + offset};
    }
    offset += stream_limit_res.len;
    ref_stream_limit = nullptr;

    return {true, offset};
}

EncodingResult encode(const StreamsBlocked& in, uint8_t*& out) {
}

size_t NewConnectionId::byte_size() const {
    return type.byte_size() + sequence_number.byte_size()
        + retire_prior_to.byte_size() + 4 + 16;
}
EncodingResult decode(uint8_t* in, NewConnectionId& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_sequence_number = in + offset;

    auto sequence_number_res = zclp_encoding::decode_vl_integer(
        ref_sequence_number, out.sequence_number);
    if (!sequence_number_res) {
        ref_sequence_number = nullptr;
        return {false, sequence_number_res.len + offset};
    }
    offset += sequence_number_res.len;
    ref_sequence_number = nullptr;

    uint8_t* ref_retire_prior_to = in + offset;

    auto retire_prior_to_res = zclp_encoding::decode_vl_integer(
        ref_retire_prior_to, out.retire_prior_to);
    if (!retire_prior_to_res) {
        ref_retire_prior_to = nullptr;
        return {false, retire_prior_to_res.len + offset};
    }
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

EncodingResult encode(const NewConnectionId& in, uint8_t*& out) {
}

size_t RetireConnectionId::byte_size() const {
    return type.byte_size() + sequence_number.byte_size();
}
EncodingResult decode(uint8_t* in, RetireConnectionId& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_sequence_number = in + offset;

    auto sequence_number_res = zclp_encoding::decode_vl_integer(
        ref_sequence_number, out.sequence_number);
    if (!sequence_number_res) {
        ref_sequence_number = nullptr;
        return {false, sequence_number_res.len + offset};
    }
    offset += sequence_number_res.len;
    ref_sequence_number = nullptr;

    return {true, offset};
}

EncodingResult encode(const RetireConnectionId& in, uint8_t*& out) {
}

size_t PathChallange::byte_size() const {
    return type.byte_size() + 8;
}
EncodingResult decode(uint8_t* in, PathChallange& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_data = in + offset;

    memcpy(&out.data, ref_data, 8);
    ref_data = nullptr;

    return {true, offset};
}

EncodingResult encode(const PathChallange& in, uint8_t*& out) {
}

size_t PathResponse::byte_size() const {
    return type.byte_size() + 8;
}
EncodingResult decode(uint8_t* in, PathResponse& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_data = in + offset;

    memcpy(&out.data, ref_data, 8);
    ref_data = nullptr;
    return {true, offset};
}

EncodingResult encode(const PathResponse& in, uint8_t*& out) {
}

size_t ConnectionClose::byte_size() const {
    return type.byte_size() + error.byte_size() + frame_type.byte_size()
        + phrase_len.byte_size();
}
EncodingResult decode(uint8_t* in, ConnectionClose& out) {
    size_t offset = 0;

    uint8_t* ref_type = in + offset;

    auto type_res = zclp_encoding::decode_vl_integer(ref_type, out.type);
    if (!type_res) {
        ref_type = nullptr;
        return {false, type_res.len + offset};
    }
    offset += type_res.len;
    ref_type = nullptr;

    uint8_t* ref_error = in + offset;

    auto error_res = zclp_encoding::decode_vl_integer(ref_error, out.error);
    if (!error_res) {
        ref_error = nullptr;
        return {false, error_res.len + offset};
    }
    offset += error_res.len;
    ref_error = nullptr;

    uint8_t* ref_frame_type = in + offset;

    auto frame_type_res =
        zclp_encoding::decode_vl_integer(ref_type, out.frame_type);
    if (!frame_type_res) {
        ref_frame_type = nullptr;
        return {false, frame_type_res.len + offset};
    }
    offset += frame_type_res.len;
    ref_frame_type = nullptr;

    uint8_t* ref_phrase_len = in + offset;

    auto phrase_len_res =
        zclp_encoding::decode_vl_integer(ref_type, out.phrase_len);
    if (!phrase_len_res) {
        ref_phrase_len = nullptr;
        return {false, phrase_len_res.len + offset};
    }
    offset += phrase_len_res.len;
    ref_phrase_len = nullptr;

    uint8_t* ref_phrase = in + offset;
    out.phrase = new uint8_t[out.phrase_len]();
    memcpy(out.phrase, ref_phrase, out.phrase_len);
    offset += out.phrase_len;
    ref_phrase = nullptr;
    return {true, offset};
}

EncodingResult encode(const ConnectionClose& in, uint8_t*& out) {
}

size_t HandShakeDone::byte_size() const {
    return type.byte_size();
}
EncodingResult decode(uint8_t* in, HandShakeDone& out) {
    auto type_res = zclp_encoding::decode_vl_integer(in, out.type);
    return {type_res, type_res.len};
}

EncodingResult encode(const HandShakeDone& in, uint8_t*& out) {
}

size_t ClusterMask::byte_size() const {
    return type.byte_size() + mask_length.byte_size() + mask_length();
}

EncodingResult decode(uint8_t* in, ClusterMask& out) {
    size_t offset = 0;
    auto type_res = zclp_encoding::decode_vl_integer(in, out.type);
    if (!type_res) {
        return {type_res, type_res.len};
    }
    offset += type_res.len;

    uint8_t* mask_length_ref = in + offset;
    auto mask_length_res =
        zclp_encoding::decode_vl_integer(mask_length_ref, out.mask_length);
    if (!mask_length_res) {
        mask_length_ref = nullptr;
        return {mask_length_res, mask_length_res.len};
    }
    offset += mask_length_res.len;
    mask_length_ref = nullptr;

    uint8_t* mask_ref = in + offset;
    memcpy(out.mask, mask_ref, out.mask_length);
    offset += out.mask_length;
    mask_ref = nullptr;

    return {true, offset};
}

EncodingResult encode(const ClusterMask& in, uint8_t*& out) {
}

size_t frame_size(const Frames::FrameVariant frame) {
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
            },
            [](const Frames::ClusterMask& f) -> size_t {
                return f.byte_size();
            }},
        frame);
}

size_t frame_payload_size(std::vector<FrameVariant> payload) {
    size_t size = 0;
    for (auto x : payload)
        size += frame_size(x);
    return size;
}

FrameResult get_frame_type(uint8_t* in) {
    VariableLengthInteger FT;
    printf("Before FT_RES\n");
    auto FT_RES = zclp_encoding::decode_vl_integer(in, FT);
    printf("After FT_RES\n");
    if (!FT_RES)
        return {false};
    switch (FT) {
        /*
            Each Frame has it's own ::decode(), method which is responsible for
            decoding frame from raw bytes.
        */
    case 0: {
        Padding out;
        if (!decode(in, out))
            return {false};
        ;
        return {true, FrameType::_Padding, out};
    } break;
    case 1: {
        Ping out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_Ping, out};
    } break;
    case 2:
    case 3: {
        Ack out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_Ack, out};
    } break;
    case 4: {
        ResetStream out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_ResetStream, out};
    } break;

    case 5: {
        StopSending out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_StopSending, out};
    } break;
    case 6: {
        Crypto out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_Crypto, out};
    } break;
    case 7: {
        NewToken out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_NewToken, out};
    } break;

    case 16: {
        MaxData out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_MaxData, out};
    } break;

    case 17: {
        MaxStreamData out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_MaxStreamData, out};
    } break;

    case 18:
    case 19: {
        MaxStreams out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_MaxStreams, out};
    } break;

    case 20: {
        DataBlocked out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_DataBlocked, out};
    } break;
    case 21: {
        StreamDataBlocked out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_StreamDataBlocked, out};
    } break;
    case 22:
    case 23: {
        StreamsBlocked out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_StreamsBlocked, out};
    } break;

    case 24: {
        NewConnectionId out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_NewConnectionId, out};
    } break;

    case 25: {
        RetireConnectionId out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_RetireConnectionId, out};
    } break;
    case 26: {
        PathChallange out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_PathChallange, out};
    } break;
    case 27: {
        PathResponse out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_PathResponse, out};
    } break;

    case 28:
    case 29: {
        ConnectionClose out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_ConnectionClose, out};
    } break;

    case 30: {
        HandShakeDone out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_HandShakeDone, out};
    } break;

    case 31: {
        ClusterMask out;
        if (!decode(in, out))
            return {false};
        return {true, FrameType::_ClusterMask, out};
    } break;

    default: {
        Stream out;
        return {true, FrameType::_Stream, out};
    }
    };
}
}  // namespace Frames

namespace Packets {

bool is_long_header(uint8_t* packet) {
    uint8_t HF = ((packet[0] >> 7) & 1);
    uint8_t FB = ((packet[0] >> 6) & 1);

    return HF == 1 && FB == 1;
}

bool is_short_header(uint8_t* packet) {
    uint8_t HF = ((packet[0] >> 7) & 1);
    uint8_t FB = ((packet[0] >> 6) & 1);

    return HF == 0 && FB == 1;
}

bool is_initial_packet(uint8_t* packet) {
    uint8_t HT = (packet[0] >> 4) & 0b11;
    return is_long_header(packet) && HT == 0;
}

bool is_0rtt_packet(uint8_t* packet) {
    uint8_t HT = (packet[0] >> 4) & 0b11;
    return is_long_header(packet) && HT == 1;
}

bool is_handshake_packet(uint8_t* packet) {
    uint8_t HT = (packet[0] >> 4) & 0b11;
    return is_long_header(packet) && HT == 2;
}

bool is_retry_packet(uint8_t* packet) {
    uint8_t HT = (packet[0] >> 4) & 0b11;
    return is_long_header(packet) && HT == 3;
}

bool operator!(const PacketType& type) {
    return type == PACKET_UNKNOWN;
}

void printPacketType(enum PacketType type) {
    switch (type) {
    case PACKET_UNKNOWN:
        printf("Packet Type: PACKET_UNKNOWN\n");
        break;
    case PACKET_INITIAL:
        printf("Packet Type: PACKET_INITIAL\n");
        break;
    case PACKET_0RTT:
        printf("Packet Type: PACKET_0RTT\n");
        break;
    case PACKET_HANDSHAKE:
        printf("Packet Type: PACKET_HANDSHAKE\n");
        break;
    case PACKET_RETRY:
        printf("Packet Type: PACKET_RETRY\n");
        break;
    case PACKET_SHORT_HEADER:
        printf("Packet Type: PACKET_SHORT_HEADER\n");
        break;
    case PACKET_LONG_HEADER:
        printf("Packet Type: PACKET_LONG_HEADER\n");
        break;
    default:
        printf("Packet Type: UNKNOWN\n");
        break;
    }
}

PacketType get_packet_type(uint8_t* packet) {
    uint8_t first_byte = packet[0];

    uint8_t HF = (first_byte >> 7) & 1;
    uint8_t FB = (first_byte >> 6) & 1;

    if (HF == 0 && FB == 1)
        return PACKET_SHORT_HEADER;

    if (HF == 1 && FB == 1) {
        uint8_t HT = (first_byte >> 4) & 0b11;
        printf("Type: %u\n", HT);
        switch (HT) {
        case 0:
            return PACKET_INITIAL;
        case 1:
            return PACKET_0RTT;
        case 2:
            return PACKET_HANDSHAKE;
        case 3:
            return PACKET_RETRY;
        default:
            return PACKET_UNKNOWN;
        }
    }

    return PACKET_UNKNOWN;
}

size_t StatelessReset::byte_size() const {
    /*
        16 bytes token
        1 byte HF && FBs
        N bytes unpredictable_bits.size()
    */
    return 16 + 1 + unpredictable_bits.byte_size();
}

size_t VersionNegotiation::byte_size() const {
    /*
        1 byte HF && unused
        12 bytes version_id && destination_connection_id &&
        source_connection_id
        4 * N bytes supported_versions
    */
    return 13 + 4 * supported_versions.size();
}

size_t LongHeader::byte_size() const {
    /*
        1 byte - ..version_id
        12 bytes version_id + destination_connection_id +
       source_connection_id
    */
    return 13;
}

LongHeader::LongHeader() noexcept : header_form(1), fixed_bit(1) {
}
LongHeader::LongHeader(PacketType PT) noexcept : header_form(1), fixed_bit(1) {
    switch (PT) {
    case PACKET_INITIAL:
        packet_type = 0;
        break;
    case PACKET_0RTT:
        packet_type = 1;
        break;
    case PACKET_HANDSHAKE:
        packet_type = 2;
        break;
    case PACKET_RETRY:
        packet_type = 3;
        break;
    default:
        printf("Packet Type: UNKNOWN\n");
        break;
    }
}

size_t ProtectedLongHeader::byte_size() const {
    /*
        1 byte - ..version_id
        12 bytes version_id + destination_connection_id +
       source_connection_id
    */
    return 13;
}

ProtectedLongHeader::ProtectedLongHeader() noexcept
    : header_form(1), fixed_bit(1) {
}
ProtectedLongHeader::ProtectedLongHeader(PacketType PT) noexcept
    : header_form(1), fixed_bit(1) {
    switch (PT) {
    case PACKET_INITIAL:
        packet_type = 0;
        break;
    case PACKET_0RTT:
        packet_type = 1;
        break;
    case PACKET_HANDSHAKE:
        packet_type = 2;
        break;
    case PACKET_RETRY:
        packet_type = 3;
        break;
    default:
        printf("Packet Type: UNKNOWN\n");
        break;
    }
}

size_t Initial::byte_size() const {
    return header.byte_size() + token_length() + length();
}

size_t ZeroRTT::byte_size() const {
    return header.byte_size() + length();
}

size_t HandShake::byte_size() const {
    return header.byte_size() + length();
}

size_t Retry::byte_size() const {
    /*
        token len external
        ||
        Retry packet size - header - integrity_tag size
    */
    return header.byte_size() + 16;
}

size_t ShortHeader::byte_size() const {
    /*

    */
    return 2 + 4 + Frames::frame_payload_size(payload);
}

ShortHeader::ShortHeader() noexcept : header_form(0), fixed_bit(1) {
}

}  // namespace Packets

namespace Structs {}  // namespace Structs
