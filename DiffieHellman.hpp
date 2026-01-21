#ifndef DIFFIE_HELLMAN_HPP
#define DIFFIE_HELLMAN_HPP

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <openssl/rand.h>


const uint64_t DH_PRIME = 2147483647; 
const uint64_t DH_GENERATOR = 16807; 

class DiffieHellman {
private:
    uint64_t private_key;
    uint64_t public_key;

   
    uint64_t power(uint64_t base, uint64_t exp) {
        uint64_t res = 1;
        base = base % DH_PRIME;
        while (exp > 0) {
            if (exp % 2 == 1) res = (res * base) % DH_PRIME;
            exp = exp >> 1;
            
            base = (base * base) % DH_PRIME;
        }
        return res;
    }

public:
    DiffieHellman() {
       
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&private_key), sizeof(private_key)) != 1) {
            throw std::runtime_error("FATAL: Failed to generate random private key.");
        }
        
     
        private_key = (private_key % (DH_PRIME - 2)) + 1; 
        
        public_key = power(DH_GENERATOR, private_key);
    }

    uint64_t get_public_key() const {
        return public_key;
    }

    uint64_t compute_shared_secret(uint64_t other_public_key) {
        return power(other_public_key, private_key);
    }
};

#endif