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
#include <chrono>
#include <cmath>

#include "DiffieHellman.hpp"
#include "CryptoManager.hpp"
#include "Protocol.hpp"

const int PORT = 8080;
const int BUFFER_SIZE = 4096;

const char* TARGET_IP = "127.0.0.1"; 
const int TARGET_PORT = 9999;

class SSHServer {
    int server_fd; //file descriptor
    //linux/unix os'lerde her şey bir dosyadır. 
    //internet bağlantısı socket de bir dosyadır.
    //os açtığımız her şeye bir sıra numarası id verir.
    //server_fd=3 dediysek os 3 numaralı dosya benim 8080 portunu dinleyen soketimizdir.
    //oluşturduğumuz soketi daha sonra bind veya listen fonksiyonlarında çağırabilmek için bir id no ve server_fd değişkeninde tuttuk.

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
        std::cout << "[INFO] [Client " << client_socket << "] Connected. Starting Handshake..." << std::endl;

        // burada eksik olan istatik sayaçlarını ekledim.
        auto start_time=std::chrono::high_resolution_clock::now();
        long long total_signal_bytes=0; //bu payload
        long long total_noise_bytes=0; //header+hmac+padding
        long long total_throughput_bytes=0; // bu da bandwidth iöin toplam trafik

        DiffieHellman dh;
        uint64_t my_public_key = dh.get_public_key();
        uint64_t client_public_key = 0;

        PacketHeader kex_header;
        if (!recv_all(client_socket, &kex_header, sizeof(kex_header))) {
            close(client_socket); return;
        }
        
        if (kex_header.type != CMD_KEX) {
            std::cerr << "[ERROR] [Client " << client_socket << "] Handshake failed: Expected CMD_KEX." << std::endl;
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

        std::cout << "[DEBUG] [Client " << client_socket << "] Shared Secret Established." << std::endl;

        PacketHeader iv_header;
        if (!recv_all(client_socket, &iv_header, sizeof(iv_header))) {
            close(client_socket); return;
        }

        if (iv_header.type != CMD_IV) {
            std::cerr << "[ERROR] [Client " << client_socket << "] Handshake failed: Expected CMD_IV." << std::endl;
            close(client_socket); return;
        }

        uint32_t iv_len = ntohl(iv_header.payload_size);
        std::vector<char> iv_buffer(iv_len);
        if (!recv_all(client_socket, iv_buffer.data(), iv_len)) {
            close(client_socket); return;
        }

        std::string iv_str(iv_buffer.begin(), iv_buffer.end());
        crypto->set_iv(iv_str);
        
        std::cout << "[SUCCESS] [Client " << client_socket << "] Secure Tunnel Established! IV Set." << std::endl;

        int target_fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(TARGET_PORT);
        inet_pton(AF_INET, TARGET_IP, &target_addr.sin_addr);

        bool tunnel_active = false;
        if (connect(target_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            std::cerr << "[WARN] [Client " << client_socket << "] Target ("<< TARGET_PORT <<") unreachable. Tunneling disabled, File Transfer Active." << std::endl;
            close(target_fd);
            target_fd = -1;
        } else {
            std::cout << "[INFO] [Client " << client_socket << "] Tunnel Connected to Target." << std::endl;
            tunnel_active = true;
        }

        std::string filename = "received_" + std::to_string(client_socket) + ".dat";
        std::ofstream outfile;
        bool file_open = false;
        char buffer[BUFFER_SIZE];

        fd_set readfds;
        while (true) {
            FD_ZERO(&readfds);
            FD_SET(client_socket, &readfds);
            if (tunnel_active) FD_SET(target_fd, &readfds);
            
            int max_sd = (tunnel_active) ? std::max(client_socket, target_fd) : client_socket;

            if (select(max_sd + 1, &readfds, NULL, NULL, NULL) < 0) break;

            //burası clienttan gelen veriyi alıyor
            if (FD_ISSET(client_socket, &readfds)) {
                PacketHeader header;
                if (!recv_all(client_socket, &header, sizeof(header))) break;

                //snr hesabı için header'ı da bir gürültü olarak sayarız. (overhead)
                total_noise_bytes+=sizeof(header);
                total_throughput_bytes+=sizeof(header);
                
                header.magic_number = ntohl(header.magic_number);
                header.payload_size = ntohl(header.payload_size);
                uint8_t type = header.type;

                if (header.magic_number != MAGIC_NUMBER) break;
                if (type == CMD_CLOSE) {
                    std::cout << "[INFO] [Client " << client_socket << "] Client requested disconnect." << std::endl;
                    break;
                }
                
                std::vector<char> body(header.payload_size);
                if (!recv_all(client_socket, body.data(), header.payload_size)) break;

                total_throughput_bytes += header.payload_size;

                Packet encrypted_packet(body.begin(), body.end());

                std::string received_hmac((char*)header.hmac, 32);
                if (!crypto->verify_hmac(encrypted_packet, received_hmac)) {
                    std::cerr << "[SECURITY] [Client " << client_socket << "] HMAC mismatch. Dropping." << std::endl;
                    continue;
                }

                Packet decrypted_packet = crypto->decrypt(encrypted_packet);

                total_signal_bytes += decrypted_packet.size();
                total_noise_bytes += (encrypted_packet.size() - decrypted_packet.size());
                
                if (type == CMD_TUNNEL_DATA) {
                    if (tunnel_active) {
                        send_all(target_fd, decrypted_packet.data(), decrypted_packet.size());
                    }
                } 
                else if (type == CMD_FILENAME) {
                    std::string received_name(decrypted_packet.begin(), decrypted_packet.end());
                    size_t slash = received_name.find_last_of("/\\");
                    if (slash != std::string::npos) received_name = received_name.substr(slash + 1);

                    filename = "received_" + received_name;
                    outfile.open(filename, std::ios::binary);
                    file_open = true;
                    std::cout << "[FILE] [Client " << client_socket << "] Receiving: " << filename << std::endl;

                } else if (type == CMD_DATA) {
                    if (!file_open) {
                        outfile.open(filename, std::ios::binary);
                        file_open = true;
                    }
                    outfile.write(decrypted_packet.data(), decrypted_packet.size());
                }
            }

            //burası tagrettan gelen verimiz asıl tunneling kısmı
            if (tunnel_active && FD_ISSET(target_fd, &readfds)) {
                int valread = read(target_fd, buffer, BUFFER_SIZE);
                if (valread <= 0) break; 

                Packet raw_response(buffer, valread);
                total_signal_bytes += raw_response.size();

                Packet encrypted_response = crypto->encrypt(raw_response);

                PacketHeader resp_header;
                resp_header.magic_number = htonl(MAGIC_NUMBER);
                resp_header.type = CMD_TUNNEL_DATA;
                resp_header.payload_size = htonl((uint32_t)encrypted_response.size());
                
                std::string hmac = crypto->compute_hmac(encrypted_response);
                memcpy(resp_header.hmac, hmac.data(), 32);

                send_all(client_socket, &resp_header, sizeof(resp_header));
                send_all(client_socket, encrypted_response.data(), encrypted_response.size());

                total_noise_bytes += sizeof(resp_header);
                total_noise_bytes += (encrypted_response.size() - raw_response.size());
                total_throughput_bytes += sizeof(resp_header) + encrypted_response.size();
            }
        }

        if(outfile.is_open()) outfile.close();
        if(tunnel_active) close(target_fd);
        close(client_socket);
        std::cout << "[INFO] [Client " << client_socket << "] Session Ended." << std::endl;

        auto end_time=std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration=end_time-start_time;
        double time_sec=duration.count();
        if(time_sec<=0) time_sec=0.001;

        double bandwidth_mbps= (total_throughput_bytes*8.0)/(time_sec*1000000.0);

        if(total_noise_bytes==0) total_noise_bytes=1;
        double snr_ratio=(double)total_signal_bytes/(double)total_noise_bytes;
        double snr_db=10*log10(snr_ratio);

        std::cout << "\n==========================================" << std::endl;
        std::cout << "           SESSION PERFORMANCE REPORT     " << std::endl;
        std::cout << "==========================================" << std::endl;
        std::cout << " CLIENT ID     : " << client_socket << " (Multi-client Supported)" << std::endl;
        std::cout << " DURATION      : " << std::fixed << std::setprecision(4) << time_sec << " s" << std::endl;
        std::cout << " TOTAL DATA    : " << total_throughput_bytes << " bytes processed" << std::endl;
        std::cout << " ------------------------------------------" << std::endl;
        std::cout << " [METRIC] BANDWIDTH : " << std::fixed << std::setprecision(2) << bandwidth_mbps << " Mbps" << std::endl;
        std::cout << " [METRIC] SNR       : " << snr_db << " dB" << std::endl;
        std::cout << "          (Signal: " << total_signal_bytes << " B / Noise: " << total_noise_bytes << " B)" << std::endl;
        std::cout << "==========================================\n" << std::endl;

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

        std::cout << "SSH Secure Tunnel Server (Hybrid Mode: Tunnel + File) - Port " << PORT << std::endl;
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