#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <memory>
#include <thread>

#include "DiffieHellman.hpp"
#include "CryptoManager.hpp"
#include "Protocol.hpp"

const int PORT = 8080;
const char* SERVER_IP = "127.0.0.1";
const int BUFFER_SIZE = 4096;

class SSHClient {
    int socket_fd;
    std::unique_ptr<CryptoManager> crypto;

public:
    SSHClient() : socket_fd(-1) {}

    ~SSHClient() {
        if (socket_fd != -1) close(socket_fd);
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

    bool connect_and_handshake() {
        struct sockaddr_in server_address;

        if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket creation failed");
            return false;
        }

        server_address.sin_family = AF_INET;
        server_address.sin_port = htons(PORT);

        if (inet_pton(AF_INET, SERVER_IP, &server_address.sin_addr) <= 0) {
            perror("Invalid address");
            return false;
        }

        if (connect(socket_fd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
            perror("Connection failed");
            return false;
        }

        std::cout << "[INFO] Connected to Server. Performing Handshake..." << std::endl;

        DiffieHellman dh;
        uint64_t my_public_key = dh.get_public_key();
        
        PacketHeader kex_header;
        kex_header.magic_number = htonl(MAGIC_NUMBER);
        kex_header.type = CMD_KEX;
        kex_header.payload_size = htonl(sizeof(my_public_key));
        memset(kex_header.hmac, 0, 32);

        if (!send_all(socket_fd, &kex_header, sizeof(kex_header))) return false;
        if (!send_all(socket_fd, &my_public_key, sizeof(my_public_key))) return false;

        PacketHeader srv_header;
        if (!recv_all(socket_fd, &srv_header, sizeof(srv_header))) return false;

        uint64_t server_public_key;
        if (!recv_all(socket_fd, &server_public_key, sizeof(server_public_key))) return false;

        uint64_t shared_secret = dh.compute_shared_secret(server_public_key);
        crypto = std::make_unique<CryptoManager>(shared_secret);

        crypto->generate_random_iv();
        std::string iv_str = crypto->get_iv_as_string();

        PacketHeader iv_header;
        iv_header.magic_number = htonl(MAGIC_NUMBER);
        iv_header.type = CMD_IV;
        iv_header.payload_size = htonl(iv_str.size());
        
        if (!send_all(socket_fd, &iv_header, sizeof(iv_header))) return false;
        if (!send_all(socket_fd, iv_str.data(), iv_str.size())) return false;

        std::cout << "[SUCCESS] Handshake Complete. Secure Tunnel Established." << std::endl;
        return true;
    }

    void perform_tunnel_test() {
        if (!crypto) return;

        std::string msg = "GET / HTTP/1.1 (Tunnel Test from Client " + std::to_string(getpid()) + ")";
        
        Packet enc = crypto->encrypt(msg);
        std::string hmac = crypto->compute_hmac(enc);

        PacketHeader h;
        h.magic_number = htonl(MAGIC_NUMBER);
        h.type = CMD_TUNNEL_DATA;
        h.payload_size = htonl(enc.size());
        memcpy(h.hmac, hmac.data(), 32);

        send_all(socket_fd, &h, sizeof(h));
        send_all(socket_fd, enc.data(), enc.size());
        
        std::cout << "[TUNNEL] Request sent through tunnel: " << msg << std::endl;

        PacketHeader resp_h;
        if (recv_all(socket_fd, &resp_h, sizeof(resp_h))) {
            resp_h.payload_size = ntohl(resp_h.payload_size);
            if (resp_h.payload_size > 0 && resp_h.payload_size < BUFFER_SIZE * 10) {
                std::vector<char> body(resp_h.payload_size);
                recv_all(socket_fd, body.data(), resp_h.payload_size);
                
                Packet resp_enc(body.begin(), body.end());
                Packet resp_dec = crypto->decrypt(resp_enc);
                std::string response(resp_dec.begin(), resp_dec.end());
                
                std::cout << "[TUNNEL] Response received from Target: " << response << std::endl;
            }
        }
    }

    void send_file(const std::string& filename) {
        if (!crypto) return;

        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::cerr << "ERROR: Could not open file '" << filename << "'" << std::endl;
            return;
        }
        std::streamsize file_size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (file_size == 0) {
            std::cerr << "ERROR: File is empty." << std::endl;
            return;
        }

        std::cout << "[INFO] Sending file: " << filename << " (" << file_size << " bytes)" << std::endl;

        std::string basename = filename.substr(filename.find_last_of("/\\") + 1);
        Packet name_packet(basename.begin(), basename.end());
        Packet encrypted_name = crypto->encrypt(name_packet);

        PacketHeader name_header;
        name_header.magic_number = htonl(MAGIC_NUMBER);
        name_header.type = CMD_FILENAME;
        name_header.payload_size = htonl(encrypted_name.size());
        
        std::string hmac_name = crypto->compute_hmac(encrypted_name);
        memcpy(name_header.hmac, hmac_name.data(), 32);

        if (!send_all(socket_fd, &name_header, sizeof(name_header))) return;
        if (!send_all(socket_fd, encrypted_name.data(), encrypted_name.size())) return;

        char buffer[BUFFER_SIZE];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            size_t bytes_read = file.gcount();
            if (bytes_read == 0) break;

            Packet chunk(buffer, buffer + bytes_read);
            Packet encrypted_chunk = crypto->encrypt(chunk);

            PacketHeader header;
            header.magic_number = htonl(MAGIC_NUMBER);
            header.type = CMD_DATA;
            header.payload_size = htonl(encrypted_chunk.size());

            std::string hmac_data = crypto->compute_hmac(encrypted_chunk);
            memcpy(header.hmac, hmac_data.data(), 32);

            if (!send_all(socket_fd, &header, sizeof(header))) break;
            if (!send_all(socket_fd, encrypted_chunk.data(), encrypted_chunk.size())) break;
        }

        std::cout << "[SUCCESS] File sent successfully." << std::endl;
    }

    void close_connection() {
        PacketHeader h_close;
        h_close.magic_number = htonl(MAGIC_NUMBER);
        h_close.type = CMD_CLOSE;
        h_close.payload_size = 0;
        memset(h_close.hmac, 0, 32);
        send_all(socket_fd, &h_close, sizeof(h_close));
        close(socket_fd);
        socket_fd = -1;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
        return 1;
    }

    SSHClient client;
    if (client.connect_and_handshake()) {
        client.perform_tunnel_test();
        client.send_file(argv[1]);
        client.close_connection();
    }
    return 0;
}