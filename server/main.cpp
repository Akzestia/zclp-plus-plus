#include <cstdint>
#include <cstdio>

#include "../tokio-cpp/tokio.hpp"
#include "server.h"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Please provide listener & sender ports\n./server listener_port "
               "sender_port\n");
        return -1;
    }

    uint16_t listener_port = std::atoi(argv[1]);
    uint16_t sender_port = std::atoi(argv[2]);

    // Create a server instance, Server(listener_port, sender_port)
    Server server(listener_port, sender_port);

    // Just Return server.run() xD
    return server.run();
};
