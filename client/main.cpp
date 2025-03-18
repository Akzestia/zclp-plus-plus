#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>

#include "client.h"

int main(int argc, char* argv[]) {
    zclp_tls::init();

    Client client(1111);

    std::thread dt = std::thread([&client]() {
        if (!client.run())
            throw "Failed to start listener.";
    });
    dt.detach();

    if (!client.connect())
        return -1;

    const char* message = "Hello Server";
    while (true) {
        uint8_t mem[strlen(message)];
        memcpy(mem, message, strlen(message));

        auto res = client.send(mem, strlen(message));

        if (!res) {
            printf("\nFailed\n");
        }
        getchar();
    }

    getchar();
    if (dt.joinable())
        dt.join();
};
