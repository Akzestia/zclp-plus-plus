#include <arpa/inet.h>

#include <atomic>
#include <cstdint>

#include "../zclp++.hpp"
#include "../zclp_utils/zclp_utils.hpp"

struct Client {
    [[nodiscard]] bool run();
    [[nodiscard]] Client(uint16_t port) noexcept;
    void process_udp_pack(uint8_t* packet, ssize_t len);
    [[nodiscard]] bool send(uint8_t* message, ssize_t len);
    [[nodiscard]] bool connect();
    // connection with resumption ticket
    [[nodiscard]] bool reconnect();
    [[nodiscard]] bool disconnect();

  private:
    int m_socket_fd;
    struct sockaddr_in m_addr;
    uint16_t m_port;
    const int m_max_mtu;
    zclp_tls::zclp_tls_arena m_tls;

    std::atomic<bool> m_is_running;
};
