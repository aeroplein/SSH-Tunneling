#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint> 

const uint32_t MAGIC_NUMBER = 0xDEC0DED1; 

enum PacketType: uint8_t {
    CMD_AUTH = 1, 
    CMD_DATA = 2, 
    CMD_CLOSE = 3, 
    CMD_FILENAME = 4,
    CMD_TUNNEL_DATA = 5,
    CMD_KEX = 6,      // Handshake: Exchange Public Keys (Plaintext)
    CMD_IV = 7        // Handshake: Exchange AES IV (Plaintext)
};

#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic_number; 
    uint8_t type; 
    uint32_t payload_size;
    
    // HMAC-SHA256 for integrity.
    // NOTE: For CMD_KEX and CMD_IV, this field is IGNORED (filled with 0s)
    // because the keys are not yet established.
    unsigned char hmac[32]; 
};
#pragma pack(pop)

#endif