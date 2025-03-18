#include "client.h"

#include <netdb.h>
#include <openssl/crypto.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../tokio-cpp/tokio.hpp"
#include "../zclp_utils/zclp_utils.h"
#include "client_errors.h"

/*
    Function results

    All functions MUST return struct result, with minimum implementation of
    success and result. Optionally containing additional fields.

    struct Result {
        type success
        type data | result | payload
        ..
    };2

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

Client::Client(uint16_t port) noexcept : m_port(port), m_max_mtu(1500) {
    auto result_pb = m_tls.pub_key_to_bytes();
    auto result_pr = m_tls.private_key_to_bytes();

    m_tls.strip_pem_formatting(result_pb->result, result_pb->len);
    m_tls.strip_pem_formatting(result_pr->result, result_pr->len);
    printf("%.*s\n", (int)result_pb->len, result_pb->result);
    printf("%.*s\n", (int)result_pr->len, result_pr->result);

    delete result_pb;
    delete result_pr;
    result_pb = nullptr;
    result_pr = nullptr;

    /*
        Request | Response Connection

        This connection is only used for authentication, cluster setup
        and any other operations which doesn't require client to client
        communication.

        When client object is being constructed first cluster mask will be
        the one of the main domain [example.com]

        During the application lifecycle mask will change depending on selected
        cluster and type of operation that will be performed.
    */
    m_req_res_con.id = zclp_uint::u32_rand();
    m_req_res_con.type = Structs::C_Type::ACS;
    m_req_res_con.destination_cluster_mask = "zurui.io";
}

ZclpResult Client::connect() {
    /*
        Connect()

        This method is only used for establishing connection
        with servers (Authentication, Cluster Selection, User actions such as
        Updating info, user name etc.) and not with other clients.

        Connection with Media servers, other clients etc. must be implemented in
        separate method, and have different approach rather than simple TLS 1.3
        handshake over QUIC Transport
    */

    Packets::Initial initial_packet;
    initial_packet.header.source_connection_id = m_req_res_con.id;
    initial_packet.header.destination_connection_id = zclp_uint::u32_rand();

    Frames::Crypto crypto_frame;

    uint8_t* initial_packet_out_buff;
    auto encoding_result = zclp_encoding::encode_initial_packet(
        initial_packet, initial_packet_out_buff);

    if (!encoding_result) {
        return ZclpResult::Failure(
            client_errors::EncodingError::EncodingFailed);
    }

    ZclpResult result =
        Client::send(initial_packet_out_buff, encoding_result.len);
    return result;
}

ZclpResult Client::run() {
    m_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_socket_fd < 0) {
        return ZclpResult::Failure(
            client_errors::SetupError::SocketCreationFailed);
    }

    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(m_port);
    m_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(m_socket_fd, (struct sockaddr*)&m_addr, sizeof(sockaddr)) < 0) {
        close(m_socket_fd);
        return ZclpResult::Failure(client_errors::SetupError::SocketBindFailed);
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
    return ZclpResult::Success();
}

ZclpResult Client::send(uint8_t* message, ssize_t len) {
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(6666);

    // Using Addr info to resolve DNS (zurui.io -> 127.0.0.1)
    // Local DNS masks
    std::string dest_host = m_req_res_con.destination_cluster_mask.value();
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(dest_host.c_str(), NULL, &hints, &res) != 0)
        return ZclpResult::Failure(
            client_errors::DNS_Error::AddressParsingFailed);

    dest_addr.sin_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
    freeaddrinfo(res);

    ssize_t sent_len = sendto(m_socket_fd, message, len, 0,
                              (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent_len < 0)
        return ZclpResult::Failure(client_errors::SocketError::FailedToSend);

    return ZclpResult::Success();
}

void Client::process_udp_pack(uint8_t* packet, ssize_t len) {
    printf("Packet len: %lu\n", len);
    printf("Received message: %.*s\n", (int)len, packet);
    delete[] packet;
    packet = nullptr;
}
