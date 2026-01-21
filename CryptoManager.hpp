#ifndef CRYPTOMANAGER_HPP
#define CRYPTOMANAGER_HPP

#include <string>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <cstring>         
#include <openssl/evp.h>
#include <openssl/hmac.h> 
#include <openssl/rand.h> 
#include <memory>


using Packet = std::string;

class CryptoManager {
private:
    unsigned char aes_key[32];
    unsigned char hmac_key[32];
    unsigned char iv[16];
    bool iv_set = false;

    EVP_CIPHER_CTX* encrypt_ctx;
    EVP_CIPHER_CTX* decrypt_ctx;

 
    void sha256_hash(const void* data, size_t len, unsigned char* out_hash) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) throw std::runtime_error("FATAL: Failed to create Digest Context");

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, data, len) != 1 ||
            EVP_DigestFinal_ex(ctx, out_hash, nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("FATAL: SHA256 hash failed");
        }
        EVP_MD_CTX_free(ctx);
    }

    void init_cipher_context(EVP_CIPHER_CTX*& ctx, int enc_flag) {
        if (!iv_set) return; 
        
        
        if (ctx) EVP_CIPHER_CTX_free(ctx); 

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("FATAL: Failed to create cipher context.");
        
        
        if (EVP_CipherInit_ex(ctx, EVP_aes_256_ctr(), nullptr, aes_key, iv, enc_flag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("FATAL: Failed to initialize AES cipher.");
        }
    }

public:
    CryptoManager() : CryptoManager(0xDEADBEEFCAFEBABE) {}

    CryptoManager(uint64_t shared_secret) {
        unsigned char hash[32];

       
        sha256_hash(&shared_secret, sizeof(shared_secret), hash);
        memcpy(aes_key, hash, 32);

        
        sha256_hash(aes_key, 32, hmac_key);

        encrypt_ctx = nullptr;
        decrypt_ctx = nullptr;
    }

    ~CryptoManager() {
        if (encrypt_ctx) EVP_CIPHER_CTX_free(encrypt_ctx);
        if (decrypt_ctx) EVP_CIPHER_CTX_free(decrypt_ctx);
    }

    // Prevent copying to avoid double-free of EVP_CIPHER_CTX pointers
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;

   

    void generate_random_iv() {
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            throw std::runtime_error("FATAL: PRNG failed.");
        }
        iv_set = true;
      
        init_cipher_context(encrypt_ctx, 1);
        init_cipher_context(decrypt_ctx, 0); 
    }
    
    void set_iv(const std::string& iv_str) {
        if (iv_str.size() != 16) throw std::runtime_error("Invalid IV size.");
        memcpy(iv, iv_str.data(), 16);
        iv_set = true;
    
        init_cipher_context(decrypt_ctx, 0); 
        init_cipher_context(encrypt_ctx, 1);
    }

    std::string get_iv_as_string() const {
        return std::string(reinterpret_cast<const char*>(iv), 16);
    }

   

    Packet encrypt(const Packet& data) {
        if (!iv_set) throw std::runtime_error("Error: IV not set before encryption.");
        return process(data, encrypt_ctx);
    }

    Packet decrypt(const Packet& data) {
        if (!iv_set) throw std::runtime_error("Error: IV not set before decryption.");
        return process(data, decrypt_ctx);
    }

    std::string compute_hmac(const Packet& encrypted_data) {
        unsigned char result[32];
        unsigned int len = 32;
        HMAC(EVP_sha256(), hmac_key, 32, 
             reinterpret_cast<const unsigned char*>(encrypted_data.data()), 
             encrypted_data.size(), result, &len);
        return std::string(reinterpret_cast<char*>(result), 32);
    }

    bool verify_hmac(const Packet& encrypted_data, const std::string& received_hmac) {
        if (received_hmac.size() != 32) return false;
        std::string calculated = compute_hmac(encrypted_data);
        return CRYPTO_memcmp(calculated.data(), received_hmac.data(), 32) == 0;
    }

private:
    Packet process(const Packet& data, EVP_CIPHER_CTX* ctx) {
        if (data.empty()) return "";
        if (!ctx) throw std::runtime_error("Cipher context not initialized.");

        Packet output;
        output.resize(data.size());
        int out_len = 0;

        if (EVP_CipherUpdate(ctx, 
             reinterpret_cast<unsigned char*>(&output[0]), &out_len, 
             reinterpret_cast<const unsigned char*>(data.data()), data.size()) != 1) {
            std::cerr << "[Crypto] ERROR: EVP_CipherUpdate failed." << std::endl;
            return "";
        }
        return output;
    }
};
#endif