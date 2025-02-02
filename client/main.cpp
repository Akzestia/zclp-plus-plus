#include <openssl/evp.h>

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

    getchar();
    if (dt.joinable())
        dt.join();
};
