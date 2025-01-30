#include <cstdio>

#include "../tokio-cpp/tokio.hpp"
#include "../zclp++.hpp"
#include "server.h"

int main(int argc, char* argv[]) {
    // tokio::initialize();

    Server server(8080);
    printf("x");
    if (!server.run()) {
        printf("\nFailed to start server\n");
    }

    // tokio::shutdown();
};
