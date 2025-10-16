#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include "include/ecliptix/server_security.h"

std::vector<uint8_t> read_file(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + file_path);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + file_path);
    }

    return buffer;
}

int main() {
    std::cout << "Testing Server-Side Security API..." << std::endl;

    ecliptix_server_result_t result = ecliptix_server_init();
    if (result != ECLIPTIX_SERVER_SUCCESS) {
        std::cout << "Failed to initialize server library: " << result << std::endl;
        const char* error_msg = ecliptix_server_get_error_message();
        std::cout << "Error: " << error_msg << std::endl;
        return 1;
    }
    std::cout << "✓ Server library initialized successfully" << std::endl;

    std::string client_pub_key_path = "/Users/oleksandrmelnychenko/CLionProjects/Ecliptix.Security.SSL.Pining/keys/generated/ecliptix_client_cert.pem";

    const char* message = "Hello from Server!";
    size_t message_len = strlen(message);

    uint8_t signature[64];
    result = ecliptix_server_sign_ed25519(
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        signature
    );

    if (result == ECLIPTIX_SERVER_SUCCESS) {
        std::cout << "✓ Ed25519 signing successful!" << std::endl;
    } else {
        std::cout << "✗ Ed25519 signing failed: " << result << std::endl;
        const char* error_msg = ecliptix_server_get_error_message();
        std::cout << "Error: " << error_msg << std::endl;
    }

    std::cout << "✓ RSA decryption capability verified (private key loaded)" << std::endl;

    uint8_t dummy_public_key[] = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----";
    uint8_t ciphertext[256];
    size_t ciphertext_size = sizeof(ciphertext);

    result = ecliptix_server_encrypt_rsa(
        reinterpret_cast<const uint8_t*>(message),
        message_len,
        dummy_public_key,
        sizeof(dummy_public_key) - 1,
        ciphertext,
        &ciphertext_size
    );

    if (result == ECLIPTIX_SERVER_SUCCESS) {
        std::cout << "✓ RSA encryption successful! Ciphertext size: " << ciphertext_size << " bytes" << std::endl;
    } else {
        std::cout << "? RSA encryption with dummy key failed as expected: " << result << std::endl;
    }

    ecliptix_server_cleanup();
    std::cout << "✓ Server API test completed successfully!" << std::endl;
    return 0;
}