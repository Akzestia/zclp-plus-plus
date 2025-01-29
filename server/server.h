#include <arpa/inet.h>
#include <atomic>

struct Server {
    [[nodiscard]] bool run();
    [[nodiscard]] Server() noexcept;
private:
    int m_socket_fd;
    struct sockaddr_in m_addr;
    const int m_max_mtu;

    std::atomic<bool> m_is_running;
};
