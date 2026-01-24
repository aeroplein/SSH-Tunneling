#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>

const int PORT = 9999;
const int BUFFER_SIZE = 1024;

void handle_connection(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int valread = read(client_socket, buffer, BUFFER_SIZE);
        
        if (valread <= 0) {
            break;
        }

        std::cout << "[TARGET] Message received: " << buffer << std::endl;

        const char* response = "Server (C++): Message received and processed!";
        send(client_socket, response, strlen(response), 0);
    }
    
    close(client_socket);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        return 1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        return 1;
    }

    std::cout << "--- Multi-Threaded Web Server Simulator ---" << std::endl;
    std::cout << "[INFO] Listening on 127.0.0.1:" << PORT << "..." << std::endl;

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        std::cout << "[TARGET] New Tunnel Connection Accepted!" << std::endl;
        
        std::thread t(handle_connection, new_socket);
        t.detach();
    }

    close(server_fd);
    return 0;
}