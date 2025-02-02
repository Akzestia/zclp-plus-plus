#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <string>

std::string generate_random_message(size_t length) {
    const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const size_t charset_size = sizeof(charset) - 1;
    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result += charset[rand() % charset_size];
    }
    return result;
}

//There is no server response for this test.
//It's only used to check server throughput
int main(int argc, char* argv[]) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in addr;
    // int m_port = 8080;
    addr.sin_family = AF_INET;
    // m_addr.sin_port = htons(m_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Binding failed");
        close(socket_fd);
        return 1;
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(8080);
    dest_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

    for (int i = 0; i < std::stoi(argv[1]); i++) {
        std::string random_message = generate_random_message(1500);
        ssize_t bytes_sent =
            sendto(socket_fd, random_message.c_str(), 1500, 0, (struct sockaddr*)&dest_addr,
                   sizeof(dest_addr));
        if (bytes_sent < 0) {
            perror("Send failed");
            close(socket_fd);
            return 1;
        }
    }

    close(socket_fd);
    return 0;
}
