#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <fstream>
#include <vector>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <memory>

#include "DiffieHellman.hpp"
#include "CryptoManager.hpp"
#include "Protocol.hpp"

const int PORT = 8080;
const int BUFFER_SIZE = 4096;

const char* TARGET_IP = "127.0.0.1"; 
const int TARGET_PORT = 9999;

class SSHServer {
    int server_fd;

public:
    SSHServer() : server_fd(-1) {}


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

    void handle_client_session(int client_socket) {
        std::cout << "[INFO] Client " << client_socket << " connected. Starting Handshake..." << std::endl;

   
        DiffieHellman dh;
        uint64_t my_public_key = dh.get_public_key();
        uint64_t client_public_key = 0;

        PacketHeader kex_header;
        if (!recv_all(client_socket, &kex_header, sizeof(kex_header))) {
            close(client_socket); return;
        }
        
   
        kex_header.type = kex_header.type; 
        if (kex_header.type != CMD_KEX) {
            std::cerr << "[ERROR] Handshake failed: Expected CMD_KEX." << std::endl;
            close(client_socket); return;
        }

        if (!recv_all(client_socket, &client_public_key, sizeof(client_public_key))) {
            close(client_socket); return;
        }

     
        PacketHeader my_header;
        my_header.magic_number = htonl(MAGIC_NUMBER);
        my_header.type = CMD_KEX;
        my_header.payload_size = htonl(sizeof(my_public_key));
        memset(my_header.hmac, 0, 32); 
        
        if (!send_all(client_socket, &my_header, sizeof(my_header))) return;
        if (!send_all(client_socket, &my_public_key, sizeof(my_public_key))) return;

        uint64_t shared_secret = dh.compute_shared_secret(client_public_key);
        
    
        auto crypto = std::make_unique<CryptoManager>(shared_secret);

        std::cout << "[DEBUG] Shared Secret Established." << std::endl;

    
        PacketHeader iv_header;
        if (!recv_all(client_socket, &iv_header, sizeof(iv_header))) {
            close(client_socket); return;
        }

        if (iv_header.type != CMD_IV) {
            std::cerr << "[ERROR] Handshake failed: Expected CMD_IV." << std::endl;
            close(client_socket); return;
        }

        uint32_t iv_len = ntohl(iv_header.payload_size);
        if (iv_len != 16) {
             std::cerr << "[ERROR] Invalid IV length." << std::endl;
             close(client_socket); return;
        }

        std::vector<char> iv_buffer(iv_len);
        if (!recv_all(client_socket, iv_buffer.data(), iv_len)) {
            close(client_socket); return;
        }

        std::string iv_str(iv_buffer.begin(), iv_buffer.end());
        crypto->set_iv(iv_str);
        
        std::cout << "[SUCCESS] Secure Tunnel Established! IV Set." << std::endl;

     
        int target_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(TARGET_PORT);
        inet_pton(AF_INET, TARGET_IP, &target_addr.sin_addr);

        if (connect(target_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            std::cerr << "[ERROR] Failed to connect to target." << std::endl;
            close(target_fd);
            close(client_socket);
            return;
        }
        std::cout << "[INFO] Connected to Target (example.com:80)" << std::endl;

        std::string filename = "received_" + std::to_string(client_socket) + ".dat";
        std::ofstream outfile;
        bool file_open = false;
        char buffer[BUFFER_SIZE];

        fd_set readfds;
        while (true) {
            FD_ZERO(&readfds);
            FD_SET(client_socket, &readfds);
            FD_SET(target_fd, &readfds);
            int max_sd = std::max(client_socket, target_fd);

            if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) break;

         
            if (FD_ISSET(client_socket, &readfds)) {
                PacketHeader header;
                if (!recv_all(client_socket, &header, sizeof(header))) break;

                header.magic_number = ntohl(header.magic_number);
                header.payload_size = ntohl(header.payload_size);

                if (header.magic_number != MAGIC_NUMBER) {
                    std::cerr << "[ERROR] Invalid Protocol Header." << std::endl;
                    break;
                }
                if (header.type == CMD_CLOSE) {
                    std::cout << "[INFO] Client requested disconnect." << std::endl;
                    break;
                }
                
                
                if (header.payload_size > BUFFER_SIZE + 1024) break;

                std::vector<char> body(header.payload_size);
                if (!recv_all(client_socket, body.data(), header.payload_size)) break;

                Packet encrypted_packet(body.begin(), body.end());

                
                std::string received_hmac((char*)header.hmac, 32);
                if (!crypto->verify_hmac(encrypted_packet, received_hmac)) {
                    std::cerr << "[SECURITY] HMAC mismatch. Dropping." << std::endl;
                    continue;
                }

                Packet decrypted_packet = crypto->decrypt(encrypted_packet);

                if (header.type == CMD_TUNNEL_DATA) {
                    send_all(target_fd, decrypted_packet.data(), decrypted_packet.size());
                    
                } else if (header.type == CMD_FILENAME) {
                    std::string received_name(decrypted_packet.begin(), decrypted_packet.end());
                    filename = "received_" + received_name;
                    outfile.open(filename, std::ios::binary);
                    file_open = true;
                    std::cout << "[FILE] Receiving: " << filename << std::endl;

                } else if (header.type == CMD_DATA) {
                    if (!file_open) {
                        outfile.open(filename, std::ios::binary);
                        file_open = true;
                    }
                    outfile.write(decrypted_packet.data(), decrypted_packet.size());
                }
            }

            if (FD_ISSET(target_fd, &readfds)) {
                int valread = read(target_fd, buffer, BUFFER_SIZE);
                if (valread <= 0) {
                    break; 
                }

                Packet raw_response(buffer, valread);
                Packet encrypted_response = crypto->encrypt(raw_response);

                PacketHeader resp_header;
                resp_header.magic_number = htonl(MAGIC_NUMBER);
                resp_header.type = CMD_TUNNEL_DATA;
                resp_header.payload_size = htonl((uint32_t)encrypted_response.size());
                
              
                std::string hmac = crypto->compute_hmac(encrypted_response);
                memcpy(resp_header.hmac, hmac.data(), 32);

                send_all(client_socket, &resp_header, sizeof(resp_header));
                send_all(client_socket, encrypted_response.data(), encrypted_response.size());
            }
        }

        if(outfile.is_open()) outfile.close();
        close(target_fd);
        close(client_socket);
        std::cout << "[INFO] Session Ended." << std::endl;
    }

    void start_listening() {
        struct sockaddr_in server_address_config;
        int reuse_address_flag = 1;
        socklen_t address_struct_size = sizeof(server_address_config);

        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket failed");
            exit(EXIT_FAILURE);
        }

        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_address_flag, sizeof(reuse_address_flag));
        server_address_config.sin_family = AF_INET;
        server_address_config.sin_addr.s_addr = INADDR_ANY;
        server_address_config.sin_port = htons(PORT);

        if (bind(server_fd, (struct sockaddr *)&server_address_config, sizeof(server_address_config)) < 0) {
            perror("Bind failed");
            exit(EXIT_FAILURE);
        }

        if (listen(server_fd, 3) < 0) {
            perror("Listening failed");
            exit(EXIT_FAILURE);
        }

        std::cout << "SSH Secure Tunnel Server (Port: " << PORT << ")" << std::endl;
        std::cout << "[INFO] Waiting for connections..." << std::endl;

        while (true) {
            int new_socket;
            if ((new_socket = accept(server_fd, (struct sockaddr *)&server_address_config, &address_struct_size)) < 0) {
                perror("Accept failed");
                continue;
            }

            std::thread t(&SSHServer::handle_client_session, this, new_socket);
            t.detach();
        }
    }
};

int main() {
    SSHServer server;
    server.start_listening();
    return 0;
}