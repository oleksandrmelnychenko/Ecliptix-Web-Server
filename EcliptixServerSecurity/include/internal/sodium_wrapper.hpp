#pragma once

#include <memory>
#include <string>
#include <vector>
#include <span>
#include <array>
#include <optional>
#include <sodium.h>

namespace ecliptix::sodium {


class SodiumException : public std::runtime_error {
public:
    explicit SodiumException(const std::string& message)
        : std::runtime_error(message) {}
};

class Library {
public:
    Library();
    ~Library() = default;

    Library(const Library&) = delete;
    Library& operator=(const Library&) = delete;
    Library(Library&&) = delete;
    Library& operator=(Library&&) = delete;

    static bool is_initialized() noexcept;
};


namespace memory {
    /**
     * Secure memory allocation that's locked and will be wiped on free
     */
    template<typename T>
    class SecureAllocator {
    public:
        using value_type = T;

        T* allocate(size_t n) {
            T* ptr = static_cast<T*>(sodium_malloc(n * sizeof(T)));
            if (!ptr) {
                throw std::bad_alloc();
            }
            return ptr;
        }

        void deallocate(T* ptr, size_t) noexcept {
            if (ptr) {
                sodium_free(ptr);
            }
        }
    };

    template<typename T>
    using SecureVector = std::vector<T, SecureAllocator<T>>;

    /**
     * Guaranteed memory wipe (compiler can't optimize away)
     */
    void secure_wipe(void* ptr, size_t size) noexcept;

    /**
     * Compare memory in constant time
     */
    bool constant_time_equals(const void* a, const void* b, size_t size) noexcept;

    /**
     * Lock memory pages to prevent swapping
     */
    bool lock_memory(void* ptr, size_t size) noexcept;

    /**
     * Unlock memory pages
     */
    bool unlock_memory(void* ptr, size_t size) noexcept;
}


namespace random {
    /**
     * Generate cryptographically secure random bytes
     */
    void bytes(void* buffer, size_t size);

    /**
     * Generate random bytes (templated for arrays)
     */
    template<size_t N>
    std::array<uint8_t, N> bytes() {
        std::array<uint8_t, N> result;
        bytes(result.data(), N);
        return result;
    }

    /**
     * Generate a random 32-bit integer
     */
    uint32_t uniform(uint32_t upper_bound);
}


namespace aead {
    struct EncryptionResult {
        memory::SecureVector<uint8_t> ciphertext;
        std::array<uint8_t, crypto_aead_chacha20poly1305_NPUBBYTES> nonce;

        memory::SecureVector<uint8_t> sealed_box() const;
    };

    /**
     * Encrypt data using ChaCha20-Poly1305
     * Automatically generates random nonce
     */
    EncryptionResult encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> key,
        std::span<const uint8_t> additional_data = {}
    );

    /**
     * Decrypt data using ChaCha20-Poly1305
     */
    std::optional<memory::SecureVector<uint8_t>> decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> key,
        std::span<const uint8_t, crypto_aead_chacha20poly1305_NPUBBYTES> nonce,
        std::span<const uint8_t> additional_data = {}
    );

    /**
     * Decrypt from sealed box (ciphertext + tag combined)
     */
    std::optional<memory::SecureVector<uint8_t>> decrypt_sealed(
        std::span<const uint8_t> sealed_box,
        std::span<const uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> key,
        std::span<const uint8_t, crypto_aead_chacha20poly1305_NPUBBYTES> nonce,
        std::span<const uint8_t> additional_data = {}
    );
}


namespace signature {
    /**
     * Ed25519 key pair
     */
    struct Ed25519KeyPair {
        std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> public_key;
        memory::SecureVector<uint8_t> private_key;

        Ed25519KeyPair();
        ~Ed25519KeyPair();
    };

    /**
     * Sign data with Ed25519
     */
    std::array<uint8_t, crypto_sign_BYTES> sign(
        std::span<const uint8_t> message,
        std::span<const uint8_t, crypto_sign_SECRETKEYBYTES> private_key
    );

    /**
     * Verify Ed25519 signature
     */
    bool verify(
        std::span<const uint8_t> message,
        std::span<const uint8_t, crypto_sign_BYTES> signature,
        std::span<const uint8_t, crypto_sign_PUBLICKEYBYTES> public_key
    ) noexcept;

    /**
     * Load private key from PEM data (secure)
     */
    std::optional<memory::SecureVector<uint8_t>> load_private_key_pem(
        std::span<const uint8_t> pem_data
    );

    /**
     * Load public key from PEM data
     */
    std::optional<std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>> load_public_key_pem(
        std::span<const uint8_t> pem_data
    );
}


namespace kdf {
    /**
     * Derive key using Argon2id (password-based)
     */
    memory::SecureVector<uint8_t> derive_from_password(
        std::span<const uint8_t> password,
        std::span<const uint8_t> salt,
        size_t output_length,
        uint64_t ops_limit = crypto_pwhash_OPSLIMIT_INTERACTIVE,
        size_t mem_limit = crypto_pwhash_MEMLIMIT_INTERACTIVE
    );

    /**
     * Derive key using HKDF (key-based)
     */
    memory::SecureVector<uint8_t> derive_hkdf(
        std::span<const uint8_t> input_key,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> info,
        size_t output_length
    );
}


namespace hash {
    /**
     * Blake2b hash (faster and more secure than SHA-2)
     */
    template<size_t DigestSize = crypto_generichash_BYTES>
    std::array<uint8_t, DigestSize> blake2b(std::span<const uint8_t> data) {
        static_assert(DigestSize >= crypto_generichash_BYTES_MIN &&
                     DigestSize <= crypto_generichash_BYTES_MAX);

        std::array<uint8_t, DigestSize> result;
        if (crypto_generichash(result.data(), DigestSize,
                              data.data(), data.size(),
                              nullptr, 0) != 0) {
            throw SodiumException("Blake2b hashing failed");
        }
        return result;
    }

    /**
     * Blake2b with key (for MAC)
     */
    template<size_t DigestSize = crypto_generichash_BYTES>
    std::array<uint8_t, DigestSize> blake2b_keyed(
        std::span<const uint8_t> data,
        std::span<const uint8_t> key
    ) {
        static_assert(DigestSize >= crypto_generichash_BYTES_MIN &&
                     DigestSize <= crypto_generichash_BYTES_MAX);

        if (key.size() < crypto_generichash_KEYBYTES_MIN ||
            key.size() > crypto_generichash_KEYBYTES_MAX) {
            throw SodiumException("Invalid Blake2b key size");
        }

        std::array<uint8_t, DigestSize> result;
        if (crypto_generichash(result.data(), DigestSize,
                              data.data(), data.size(),
                              key.data(), key.size()) != 0) {
            throw SodiumException("Blake2b keyed hashing failed");
        }
        return result;
    }
}


namespace utils {
    /**
     * Hex encode data
     */
    std::string to_hex(std::span<const uint8_t> data);

    /**
     * Hex decode data
     */
    std::optional<std::vector<uint8_t>> from_hex(const std::string& hex);

    /**
     * Base64 encode
     */
    std::string to_base64(std::span<const uint8_t> data);

    /**
     * Base64 decode
     */
    std::optional<std::vector<uint8_t>> from_base64(const std::string& base64);
}

}