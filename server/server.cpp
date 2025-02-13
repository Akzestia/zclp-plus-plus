#include "server.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../tokio-cpp/tokio.hpp"

Server::Server(uint16_t listener_port, uint16_t sender_port) noexcept
    : m_max_mtu(1500),
      m_listener_port(listener_port),
      m_sender_port(sender_port) {
}

bool Server::run() {
    m_listener_fd = socket(AF_INET, SOCK_DGRAM, 0);
    m_sender_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (m_listener_fd < 0 || m_sender_socket_fd < 0) {
        return false;
    }

    // Make sender non-blocking
    int flags = fcntl(m_sender_socket_fd, F_GETFL, 0);
    fcntl(m_sender_socket_fd, F_SETFL, flags | O_NONBLOCK);

    m_listener_addr.sin_family = AF_INET;
    m_listener_addr.sin_port = htons(m_listener_port);
    m_listener_addr.sin_addr.s_addr = INADDR_ANY;

    m_sender_addr.sin_family = AF_INET;
    m_sender_addr.sin_port = htons(m_sender_port);
    m_sender_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_listener_fd, (struct sockaddr*)&m_listener_addr,
             sizeof(sockaddr))
        < 0) {
        close(m_listener_fd);
        return false;
    }

    if (bind(m_sender_socket_fd, (struct sockaddr*)&m_sender_addr,
             sizeof(sockaddr))
        < 0) {
        close(m_sender_socket_fd);
        return false;
    }

    m_is_running.store(true);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(m_listener_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
    printf("Listening on [%s:%d]\n", ip_str, m_listener_port);

    char buffer[1500];
    uint64_t count = 0;
    tokio::ThreadPool pool(8);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    while (m_is_running.load(std::memory_order_relaxed)) {
        ssize_t len = recvfrom(m_listener_fd, buffer, sizeof(buffer) - 1, 0,
                               (struct sockaddr*)&client_addr, &client_len);
        if (len < 0) {
            perror("Receive failed");
            continue;
        }
        uint8_t* packet = new uint8_t[len];
        memcpy(packet, buffer, len);

        pool.assign_task([this, packet, len, client_addr]() mutable {
            process_udp_pack(packet, len);
            send_ack_pack(client_addr);
        });
        packet = nullptr;
    }
    close(m_listener_fd);
    return true;
};

void Server::process_udp_pack(uint8_t* packet, ssize_t len) {
    printf("Packet len: %lu\n", len);
    printf("Received message: %.*s\n", (int)len, packet);

    Packets::PacketType PT = Packets::get_packet_type(packet);
    if (!PT) {
        delete[] packet;
        packet = nullptr;
        return;
    }

    Packets::printPacketType(PT);
}

void Server::send_ack_pack(sockaddr_in destiantion_addr) const {
    printf("Sending ack\n");
    uint8_t* message = new uint8_t[20]();
    memset(message, 'x', 20);

    ssize_t sent_len =
        sendto(m_sender_socket_fd, message, 20, MSG_CONFIRM,
               (struct sockaddr*)&destiantion_addr, sizeof(destiantion_addr));
    if (sent_len == -1) {
        delete[] message;
        message = nullptr;
        perror("sendto failed\n");
    }
    delete[] message;
    message = nullptr;
}
