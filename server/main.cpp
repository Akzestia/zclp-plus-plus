#include <cstdio>

#include "../tokio-cpp/tokio.hpp"
#include "server.h"

int main(int argc, char* argv[]) {
    zclp_tls::init();
    Server server(6666, 6667);
    if (!server.run()) {
        printf("\nFailed to start server\n");
    }
};
