#include "client.h"

#include <openssl/crypto.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../tokio-cpp/tokio.hpp"

Client::Client(uint16_t port) noexcept : m_port(port), m_max_mtu(1500) {
    // auto result_pb = tls.pub_key_to_bytes();
    // auto result_pr = tls.private_key_to_bytes();

    // tls.strip_pem_formatting(result_pb->result, result_pb->len);
    // tls.strip_pem_formatting(result_pr->result, result_pr->len);
    // printf("%.*s\n", (int)result_pb->len, result_pb->result);
    // printf("%.*s\n", (int)result_pr->len, result_pr->result);

    // delete result_pb;
    // delete result_pr;
    // result_pb = nullptr;
    // result_pr = nullptr;
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
    dest_addr.sin_port = htons(6666);
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

bool Client::connect() {
    Packets::LongHeader header;

    header.header_form = 1;
    header.fixed_bit = 1;
    header.packet_type = 0;
    header.packet_type = 0;
    header.reserved_bits = 0;
    header.version_id = htonl(0x00000001);

    Packets::Initial packet;
    packet.header = header;
    packet.packet_number = 0;
    packet.length = 532;
    packet.token_length = 0;
    packet.token = nullptr;

    return true;
}
