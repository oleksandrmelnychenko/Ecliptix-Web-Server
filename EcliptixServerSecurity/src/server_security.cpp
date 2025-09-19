#include "ecliptix/server_security.h"
#include "internal/openssl_wrapper.hpp"

#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <cstring>
#include <fstream>
#include <vector>


namespace {

std::atomic<bool> g_initialized{false};
std::unique_ptr<ecliptix::openssl::Library> g_openssl_lib;
std::mutex g_init_mutex;

std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> g_ed25519_private_key{nullptr, EVP_PKEY_free};
std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> g_rsa_private_key{nullptr, EVP_PKEY_free};

thread_local std::string g_last_error;

void set_error(ecliptix_server_result_t, const std::string& message) {
    g_last_error = message;
}

ecliptix_server_result_t handle_exception(const std::exception& e, const char* operation) {
    std::string message = std::string(operation) + ": " + e.what();

    if (auto* ssl_ex = dynamic_cast<const ecliptix::openssl::OpenSSLException*>(&e)) {
        set_error(ECLIPTIX_SERVER_ERR_CRYPTO_FAILURE, message);
        return ECLIPTIX_SERVER_ERR_CRYPTO_FAILURE;
    }

    set_error(ECLIPTIX_SERVER_ERR_UNKNOWN, message);
    return ECLIPTIX_SERVER_ERR_UNKNOWN;
}

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

std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> load_private_key_from_file(const std::string& file_path) {
    auto key_data = read_file(file_path);

    BIO* bio = BIO_new_mem_buf(key_data.data(), static_cast<int>(key_data.size()));
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for private key");
    }

    std::unique_ptr<BIO, int(*)(BIO*)> bio_ptr(bio, BIO_free);

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        throw std::runtime_error("Failed to load private key from: " + file_path);
    }

    return std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>(pkey, EVP_PKEY_free);
}



extern "C" {

ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_init(void) {
    std::lock_guard<std::mutex> lock(g_init_mutex);

    if (g_initialized.load()) {
    }

    try {
        g_openssl_lib = std::make_unique<ecliptix::openssl::Library>();

        std::string server_keys_dir = "/Users/oleksandrmelnychenko/RiderProjects/Ecliptix/server-keys/";

        g_ed25519_private_key = load_private_key_from_file(server_keys_dir + "ecliptix_ed25519_private.pem");

        g_rsa_private_key = load_private_key_from_file(server_keys_dir + "ecliptix_server_private.pem");

        g_initialized.store(true);
        return ECLIPTIX_SERVER_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "Server library initialization");
    }
}

ECLIPTIX_SERVER_API void ECLIPTIX_SERVER_CALL ecliptix_server_cleanup(void) {
    std::lock_guard<std::mutex> lock(g_init_mutex);

    if (!g_initialized.load()) {
        return;
    }

    g_ed25519_private_key.reset();
    g_rsa_private_key.reset();
    g_openssl_lib.reset();
    g_initialized.store(false);
}

ECLIPTIX_SERVER_API const char* ECLIPTIX_SERVER_CALL ecliptix_server_get_error_message(void) {
    return g_last_error.c_str();
}


ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_encrypt_rsa(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* public_key_pem,
    size_t public_key_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_SERVER_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_SERVER_ERR_NOT_INITIALIZED;
    }

    if (!plaintext || plaintext_size == 0 || !public_key_pem || public_key_size == 0 ||
        !ciphertext || !ciphertext_size) {
        set_error(ECLIPTIX_SERVER_ERR_INVALID_PARAM, "Invalid RSA encryption parameters");
        return ECLIPTIX_SERVER_ERR_INVALID_PARAM;
    }

    if (plaintext_size > ECLIPTIX_SERVER_RSA_MAX_PLAINTEXT_SIZE) {
        set_error(ECLIPTIX_SERVER_ERR_INVALID_PARAM, "Plaintext too large for RSA encryption");
        return ECLIPTIX_SERVER_ERR_INVALID_PARAM;
    }

    if (*ciphertext_size < ECLIPTIX_SERVER_RSA_CIPHERTEXT_SIZE) {
        set_error(ECLIPTIX_SERVER_ERR_BUFFER_TOO_SMALL, "Ciphertext buffer too small");
        return ECLIPTIX_SERVER_ERR_BUFFER_TOO_SMALL;
    }

    try {
        auto public_key = ecliptix::openssl::KeyGenerator::deserialize_public_key(
            std::span<const uint8_t>(public_key_pem, public_key_size)
        );

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(public_key.get(), nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create RSA encryption context");
        }

        std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctx_ptr(ctx, EVP_PKEY_CTX_free);

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            throw std::runtime_error("Failed to initialize RSA encryption");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw std::runtime_error("Failed to set RSA OAEP padding");
        }

        size_t outlen = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext, plaintext_size) <= 0) {
            throw std::runtime_error("Failed to determine RSA output size");
        }

        std::vector<uint8_t> encrypted(outlen);
        if (EVP_PKEY_encrypt(ctx, encrypted.data(), &outlen, plaintext, plaintext_size) <= 0) {
            throw std::runtime_error("RSA encryption failed");
        }

        encrypted.resize(outlen);

        if (encrypted.size() > *ciphertext_size) {
            set_error(ECLIPTIX_SERVER_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
            return ECLIPTIX_SERVER_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(encrypted.begin(), encrypted.end(), ciphertext);
        *ciphertext_size = encrypted.size();

        return ECLIPTIX_SERVER_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "RSA encryption");
    }
}

ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_decrypt_rsa(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    uint8_t* plaintext,
    size_t* plaintext_size) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_SERVER_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_SERVER_ERR_NOT_INITIALIZED;
    }

    if (!ciphertext || ciphertext_size == 0 || !plaintext || !plaintext_size) {
        set_error(ECLIPTIX_SERVER_ERR_INVALID_PARAM, "Invalid RSA decryption parameters");
        return ECLIPTIX_SERVER_ERR_INVALID_PARAM;
    }

    if (!g_rsa_private_key) {
        set_error(ECLIPTIX_SERVER_ERR_KEY_LOAD_FAILED, "RSA private key not loaded");
        return ECLIPTIX_SERVER_ERR_KEY_LOAD_FAILED;
    }

    try {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(g_rsa_private_key.get(), nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create RSA decryption context");
        }

        std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)> ctx_ptr(ctx, EVP_PKEY_CTX_free);

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            throw std::runtime_error("Failed to initialize RSA decryption");
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            throw std::runtime_error("Failed to set RSA OAEP padding");
        }

        size_t outlen = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext, ciphertext_size) <= 0) {
            throw std::runtime_error("Failed to determine RSA output size");
        }

        std::vector<uint8_t> decrypted(outlen);
        if (EVP_PKEY_decrypt(ctx, decrypted.data(), &outlen, ciphertext, ciphertext_size) <= 0) {
            set_error(ECLIPTIX_SERVER_ERR_DECRYPTION_FAILED, "RSA decryption failed");
            return ECLIPTIX_SERVER_ERR_DECRYPTION_FAILED;
        }

        decrypted.resize(outlen);

        if (decrypted.size() > *plaintext_size) {
            set_error(ECLIPTIX_SERVER_ERR_BUFFER_TOO_SMALL, "Output buffer too small");
            return ECLIPTIX_SERVER_ERR_BUFFER_TOO_SMALL;
        }

        std::copy(decrypted.begin(), decrypted.end(), plaintext);
        *plaintext_size = decrypted.size();

        return ECLIPTIX_SERVER_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "RSA decryption");
    }
}


ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_sign_ed25519(
    const uint8_t* message,
    size_t message_size,
    uint8_t* signature) {

    if (!g_initialized.load()) {
        set_error(ECLIPTIX_SERVER_ERR_NOT_INITIALIZED, "Server library not initialized");
        return ECLIPTIX_SERVER_ERR_NOT_INITIALIZED;
    }

    if (!message || message_size == 0 || !signature) {
        set_error(ECLIPTIX_SERVER_ERR_INVALID_PARAM, "Invalid Ed25519 signing parameters");
        return ECLIPTIX_SERVER_ERR_INVALID_PARAM;
    }

    if (!g_ed25519_private_key) {
        set_error(ECLIPTIX_SERVER_ERR_KEY_LOAD_FAILED, "Ed25519 private key not loaded");
        return ECLIPTIX_SERVER_ERR_KEY_LOAD_FAILED;
    }

    try {
        std::span<const uint8_t> message_span(message, message_size);

        auto signature_vector = ecliptix::openssl::DigitalSignature::sign_ed25519(
            message_span, g_ed25519_private_key.get()
        );

        if (signature_vector.size() != ECLIPTIX_SERVER_ED25519_SIGNATURE_SIZE) {
            set_error(ECLIPTIX_SERVER_ERR_SIGNATURE_FAILED, "Invalid Ed25519 signature size");
            return ECLIPTIX_SERVER_ERR_SIGNATURE_FAILED;
        }

        std::copy(signature_vector.begin(), signature_vector.end(), signature);
        return ECLIPTIX_SERVER_SUCCESS;

    } catch (const std::exception& e) {
        return handle_exception(e, "Ed25519 signing");
    }
}

