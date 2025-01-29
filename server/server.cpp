#include "server.h"

#include <sys/socket.h>
#include <unistd.h>

Server::Server() noexcept : m_max_mtu(1500) {
}

bool Server::run() {
    m_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_socket_fd < 0) {
        return false;
    }

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(m_socket_fd);
    m_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_socket_fd, (struct sockaddr*)&m_addr, sizeof(m_socket_fd)) < 0) {
        close(m_socket_fd);
        return false;
    }

    m_is_running.store(true);

    while (m_is_running) {
    }
    return true;
};
