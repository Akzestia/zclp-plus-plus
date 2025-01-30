#include "client.h"

#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../tokio-cpp/tokio.hpp"

Client::Client(uint16_t port) noexcept : m_port(port), m_max_mtu(1500) {
}

bool Client::run() {
    m_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_socket_fd < 0) {
        return false;
    }

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(m_port);
    m_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_socket_fd, (struct sockaddr*)&m_addr, sizeof(sockaddr)) < 0) {
        close(m_socket_fd);
        return false;
    }

    m_is_running.store(true);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(m_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
    printf("Listening on [%s:%d]\n", ip_str, m_port);

    char buffer[1500];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    uint64_t count = 0;
    tokio::ThreadPool pool(4);

    while (m_is_running.load(std::memory_order_relaxed)) {
        ssize_t len = recvfrom(m_socket_fd, buffer, sizeof(buffer) - 1, 0,
                               (struct sockaddr*)&client_addr, &client_len);
        if (len < 0) {
            perror("Receive failed");
            continue;
        }
        uint8_t* packet = new uint8_t[len];
        memcpy(packet, buffer, len);

        pool.assign_task([this, packet, len, count]() mutable {
            process_udp_pack(packet, len);
        });

        packet = nullptr;
    }
    close(m_socket_fd);
    return true;
}

bool Client::send(uint8_t* message, ssize_t len) {
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(8080);
    dest_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

    ssize_t sent_len = sendto(m_socket_fd, message, len, 0,
                              (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent_len < 0)
        return false;

    return true;
}

void Client::process_udp_pack(uint8_t* packet, ssize_t len) {
    printf("Packet len: %lu\n", len);
    printf("Received message: %.*s\n", (int)len, packet);
    delete[] packet;
    packet = nullptr;
}
