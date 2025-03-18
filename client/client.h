#ifndef CLIENT_H
#define CLIENT_H
#include <arpa/inet.h>

#include <atomic>
#include <cstdint>
#include <vector>

#include "../zclp++/zclp_generics.h"
#include "../zclp_utils/zclp_utils.h"

/*
    Function results

    All functions MUST return struct result, with minimum implementation of
    success and result. Optionally containing additional fields.

    struct Result {
        type successCLIENT_ERRORS
        type data | result | payload
        ..CLIENT_ERRORS
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

using namespace zclp_generics;

struct Client {
    [[nodiscard]] ZclpResult run();
    [[nodiscard]] Client(uint16_t port) noexcept;
    void process_udp_pack(uint8_t* packet, ssize_t len);
    [[nodiscard]] ZclpResult send(uint8_t* message, ssize_t len);
    [[nodiscard]] ZclpResult connect();
    // connection with resumption ticket
    [[nodiscard]] ZclpResult reconnect();
    [[nodiscard]] ZclpResult disconnect();

  private:
    int m_socket_fd, m_send_socket_fd;
    struct sockaddr_in m_addr;
    uint16_t m_port;
    const int m_max_mtu;
    zclp_tls::zclp_tls_arena m_tls;
    /*
        Request | Response connection.
        Used for communication between client and servers
    */
    Structs::Connection m_req_res_con;
    /*
        Media server connection.
        Used for communication between multiple users,
        in case of audio or video transmission
    */
    Structs::Connection m_media_con;
    /*
        P2P connections.
        Used for communication between small amount users.
    */
    std::vector<Structs::Connection> m_p2p_con;

    std::atomic<bool> m_is_running;

    uint32_t m_version;
};

#endif  // CLIENT_H
