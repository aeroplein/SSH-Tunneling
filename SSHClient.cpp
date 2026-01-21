#include <iostream>
#include <sys/socket.h>
#include <sys/select.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <memory>     

#include "DiffieHellman.hpp"
#include "CryptoManager.hpp"
#include "Protocol.hpp"

const int REMOTE_PORT = 8080;
const int LOCAL_PORT = 9090;
const char* SERVER_IP = "127.0.0.1";
const int BUFFER_SIZE = 4096;

class SSHClient {
private:
    int ssh_socket_fd;
    int local_listener_fd;
   
    std::unique_ptr<CryptoManager> crypto; 

public:
    SSHClient() : ssh_socket_fd(-1), local_listener_fd(-1) {}

    ~SSHClient() {
        if (ssh_socket_fd != -1) close(ssh_socket_fd);
        if (local_listener_fd != -1) close(local_listener_fd);
    }

  
    bool recv_all(int sock, void* buffer, size_t len) {
        size_t total = 0;
        char* p = (char*)buffer;
        while (total < len) {
            ssize_t r = read(sock, p + total, len - total);
            if (r <= 0) return false;
            total += r;
        }
        return true;
    }

  
    bool send_all(int sock, const void* buffer, size_t len) {
        size_t total = 0;
        const char* p = (const char*)buffer;
        while (total < len) {
            ssize_t s = send(sock, p + total, len - total, 0);
            if (s <= 0) return false;
            total += s;
        }
        return true;
    }

    bool connect_to_server() {
        struct sockaddr_in server_address;
        
        if ((ssh_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation failed");
            return false;
        }

        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(REMOTE_PORT);

        if (inet_pton(AF_INET, SERVER_IP, &server_address.sin_addr) <= 0) return false;
        if (connect(ssh_socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) return false;

        std::cout << "[INFO] Connected to Server. Performing Handshake..." << std::endl;

    
        DiffieHellman dh;
        uint64_t my_pub = dh.get_public_key();
        uint64_t server_pub = 0;

        PacketHeader kex_header;
        kex_header.magic_number = htonl(MAGIC_NUMBER);
        kex_header.type = CMD_KEX;
        kex_header.payload_size = htonl(sizeof(my_pub));
        memset(kex_header.hmac, 0, 32); 
        
        if (!send_all(ssh_socket_fd, &kex_header, sizeof(kex_header))) return false;
        if (!send_all(ssh_socket_fd, &my_pub, sizeof(my_pub))) return false;

        PacketHeader resp_header;
        if (!recv_all(ssh_socket_fd, &resp_header, sizeof(resp_header))) return false;
        
       
        if (ntohl(resp_header.magic_number) != MAGIC_NUMBER || resp_header.type != CMD_KEX) {
             std::cerr << "Handshake Protocol Error" << std::endl;
             return false;
        }

        if (!recv_all(ssh_socket_fd, &server_pub, sizeof(server_pub))) return false;

        uint64_t secret = dh.compute_shared_secret(server_pub);
        crypto = std::make_unique<CryptoManager>(secret);

        crypto->generate_random_iv();
        std::string iv_str = crypto->get_iv_as_string();

        PacketHeader iv_header;
        iv_header.magic_number = htonl(MAGIC_NUMBER);
        iv_header.type = CMD_IV;
        iv_header.payload_size = htonl(iv_str.size());
        memset(iv_header.hmac, 0, 32); 

        if (!send_all(ssh_socket_fd, &iv_header, sizeof(iv_header))) return false;
        if (!send_all(ssh_socket_fd, iv_str.data(), iv_str.size())) return false;

        std::cout << "[SUCCESS] Handshake Complete. Secure Tunnel Established." << std::endl;
        return true;
    }

    bool start_local_listener() {
        struct sockaddr_in address;
        int opt = 1;

        if ((local_listener_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return false;
        setsockopt(local_listener_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(LOCAL_PORT);

        if (bind(local_listener_fd, (struct sockaddr*)&address, sizeof(address)) < 0) return false;
        if (listen(local_listener_fd, 1) < 0) return false;

        std::cout << "[INFO] Listening for local apps on port " << LOCAL_PORT << "..." << std::endl;
        return true;
    }

    void start_tunneling() {
        int app_socket_fd;
        struct sockaddr_in app_addr;
        socklen_t addrlen = sizeof(app_addr);

        std::cout << "[INFO] Waiting for local application connection..." << std::endl;
        if ((app_socket_fd = accept(local_listener_fd, (struct sockaddr*)&app_addr, &addrlen)) < 0) return;
        std::cout << "[INFO] Local App Connected. Tunnel Active." << std::endl;

        fd_set readfds;
        char buffer[BUFFER_SIZE]; 

        while (true) {
            FD_ZERO(&readfds);
            FD_SET(app_socket_fd, &readfds);
            FD_SET(ssh_socket_fd, &readfds);
            int max_sd = std::max(app_socket_fd, ssh_socket_fd);

            if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) break;

       
            if (FD_ISSET(app_socket_fd, &readfds)) {
                int valread = read(app_socket_fd, buffer, BUFFER_SIZE);
                if (valread <= 0) break; 

                Packet raw(buffer, valread);
                Packet enc = crypto->encrypt(raw);
                
                PacketHeader head;
                head.magic_number = htonl(MAGIC_NUMBER);
                head.type = CMD_TUNNEL_DATA;
                head.payload_size = htonl((uint32_t)enc.size());
                
             
                std::string hmac = crypto->compute_hmac(enc);
                memcpy(head.hmac, hmac.data(), 32);

                if (!send_all(ssh_socket_fd, &head, sizeof(head))) break;
                if (!send_all(ssh_socket_fd, enc.data(), enc.size())) break;
            }

            if (FD_ISSET(ssh_socket_fd, &readfds)) {
                PacketHeader head;
                if (!recv_all(ssh_socket_fd, &head, sizeof(head))) break; 
                
                uint32_t p_size = ntohl(head.payload_size);
                uint32_t magic = ntohl(head.magic_number);

                if (magic != MAGIC_NUMBER) {
                    std::cerr << "Protocol Error" << std::endl;
                    break;
                }
                
                if (p_size > BUFFER_SIZE + 1024) { 
                    std::cerr << "Packet too large." << std::endl;
                    break;
                }

                std::vector<char> body(p_size);
                if (!recv_all(ssh_socket_fd, body.data(), p_size)) break;

           
                Packet enc(body.begin(), body.end());
                std::string received_hmac((char*)head.hmac, 32);
                
                if (!crypto->verify_hmac(enc, received_hmac)) {
                     std::cerr << "[SECURITY] HMAC Verification Failed! Dropping packet." << std::endl;
                     continue;
                }

                Packet dec = crypto->decrypt(enc);
                send_all(app_socket_fd, dec.data(), dec.size());
            }
        }
        close(app_socket_fd);
        std::cout << "[INFO] Tunnel closed." << std::endl;
    }
};

int main() {
    SSHClient client;
    if (client.connect_to_server()) {
        if (client.start_local_listener()) {
            client.start_tunneling();
        }
    }
    return 0;
}