#include <arpa/inet.h>

#include <atomic>
#include <cstdint>

#include "../zclp_utils/zclp_utils.h"

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

    std::atomic<bool> m_is_running;
};
