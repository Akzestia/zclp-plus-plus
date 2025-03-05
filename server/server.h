#include <arpa/inet.h>
#include <sys/types.h>

#include <atomic>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "../zclp_utils/zclp_utils.h"

/*
    Function results

    All functions MUST return struct result, with minimum implementation of
    success and result. Optionally containing additional fields.

    struct Result {
        type success
        type data | result | payload
        ..
    };

    Result void func();

    ------------------------------------------------------------------------

    For placeholder values bool MUST be used.

    bool void func();

    ------------------------------------------------------------------------

    All Result structs SHOULD implement operator!();

    if(!Result){
        handle error
    }
*/

struct Server {
    [[nodiscard]] bool run();
    [[nodiscard]] Server(uint16_t listener_port, uint16_t sender_port) noexcept;
    void process_udp_pack(uint8_t* packet, ssize_t len);
    void send_ack_pack(sockaddr_in destiantion_addr) const;

  private:
    /*
        using separate sockets for recv|send,
        for non-blocking io
    */
    int m_listener_fd, m_sender_socket_fd;
    struct sockaddr_in m_listener_addr, m_sender_addr;
    uint16_t m_listener_port, m_sender_port;
    const int m_max_mtu;

    /*
        Map of existing connections within the cluster]

        unordered_map<connection_id, owned stream_ids>
    */
    std::unordered_map<uint32_t, std::vector<uint32_t>> connection_streams;
    /*
        Separate pool for each incoming packet type for faster processing.

        unordered_map<stream_id, type_payload>
    */
    std::unordered_map<uint32_t, Packets::Initial> initial_packet_pool;
    std::unordered_map<uint32_t, Packets::ZeroRTT> zero_rtt_packet_pool;
    std::unordered_map<uint32_t, Packets::HandShake> handshake_rtt_packet_pool;
    std::unordered_map<uint32_t, Packets::Retry> retry_packet_pool;

    std::atomic<bool> m_is_running;
};
