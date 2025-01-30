#include <arpa/inet.h>
#include <atomic>
#include <cstdint>

struct Server {
    [[nodiscard]] bool run();
    [[nodiscard]] Server(uint16_t port) noexcept;
    void process_udp_pack(uint8_t* packet, ssize_t len);
private:
    int m_socket_fd;
    struct sockaddr_in m_addr;
    uint16_t m_port;
    const int m_max_mtu;

    std::atomic<bool> m_is_running;
};
