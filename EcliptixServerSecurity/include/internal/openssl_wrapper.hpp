#pragma once

#include <memory>
#include <string>
#include <vector>
#include <span>
#include <functional>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

namespace ecliptix::openssl {


class OpenSSLException : public std::runtime_error {
public:
    explicit OpenSSLException(const std::string& message);
    explicit OpenSSLException(const std::string& operation, unsigned long error_code);

    unsigned long error_code() const noexcept { return error_code_; }

private:
    unsigned long error_code_ = 0;
};

std::string get_last_error();

std::string get_openssl_error_string(unsigned long error_code);

void clear_errors();


namespace detail {

struct EVP_PKEY_deleter {
    void operator()(EVP_PKEY* ptr) const { EVP_PKEY_free(ptr); }
};

struct X509_deleter {
    void operator()(X509* ptr) const { X509_free(ptr); }
};

struct X509_STORE_deleter {
    void operator()(X509_STORE* ptr) const { X509_STORE_free(ptr); }
};

struct X509_STORE_CTX_deleter {
    void operator()(X509_STORE_CTX* ptr) const { X509_STORE_CTX_free(ptr); }
};

struct EVP_MD_CTX_deleter {
    void operator()(EVP_MD_CTX* ptr) const { EVP_MD_CTX_free(ptr); }
};

struct EVP_CIPHER_CTX_deleter {
    void operator()(EVP_CIPHER_CTX* ptr) const { EVP_CIPHER_CTX_free(ptr); }
};

struct EVP_KDF_CTX_deleter {
    void operator()(EVP_KDF_CTX* ptr) const { EVP_KDF_CTX_free(ptr); }
};

struct SSL_CTX_deleter {
    void operator()(SSL_CTX* ptr) const { SSL_CTX_free(ptr); }
};

struct SSL_deleter {
    void operator()(SSL* ptr) const { SSL_free(ptr); }
};

struct BIO_deleter {
    void operator()(BIO* ptr) const { BIO_free(ptr); }
};

struct BIGNUM_deleter {
    void operator()(BIGNUM* ptr) const { BN_free(ptr); }
};

struct EC_KEY_deleter {
    void operator()(EC_KEY* ptr) const { EC_KEY_free(ptr); }
};

struct RSA_deleter {
    void operator()(RSA* ptr) const { RSA_free(ptr); }
};

struct STACK_OF_X509_deleter {
    void operator()(STACK_OF(X509)* ptr) const {
        sk_X509_pop_free(ptr, X509_free);
    }
};

}

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, detail::EVP_PKEY_deleter>;
using X509_ptr = std::unique_ptr<X509, detail::X509_deleter>;
using X509_STORE_ptr = std::unique_ptr<X509_STORE, detail::X509_STORE_deleter>;
using X509_STORE_CTX_ptr = std::unique_ptr<X509_STORE_CTX, detail::X509_STORE_CTX_deleter>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, detail::EVP_MD_CTX_deleter>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, detail::EVP_CIPHER_CTX_deleter>;
using EVP_KDF_CTX_ptr = std::unique_ptr<EVP_KDF_CTX, detail::EVP_KDF_CTX_deleter>;
using SSL_CTX_ptr = std::unique_ptr<SSL_CTX, detail::SSL_CTX_deleter>;
using SSL_ptr = std::unique_ptr<SSL, detail::SSL_deleter>;
using BIO_ptr = std::unique_ptr<BIO, detail::BIO_deleter>;
using BIGNUM_ptr = std::unique_ptr<BIGNUM, detail::BIGNUM_deleter>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, detail::EC_KEY_deleter>;
using RSA_ptr = std::unique_ptr<RSA, detail::RSA_deleter>;
using STACK_OF_X509_ptr = std::unique_ptr<STACK_OF(X509), detail::STACK_OF_X509_deleter>;


class Library {
public:
    Library();
    ~Library();

    Library(const Library&) = delete;
    Library& operator=(const Library&) = delete;
    Library(Library&&) = delete;
    Library& operator=(Library&&) = delete;

    static bool is_initialized();

private:
    static bool initialized_;
};


class Random {
public:
    static void bytes(std::span<uint8_t> buffer);
    static void bytes(uint8_t* buffer, size_t size);

    template<size_t N>
    static std::array<uint8_t, N> bytes() {
        std::array<uint8_t, N> result;
        bytes(result);
        return result;
    }

    static void seed(std::span<const uint8_t> entropy);
    static int status();
};


class KeyGenerator {
public:
    static std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> generate_ed25519();

    static std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> generate_ecdsa_p384();

    static std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> generate_rsa(int bits = 4096);

    static std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> generate_ecdh_x25519();
    static std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> generate_ecdh_p384();

    static std::vector<uint8_t> serialize_public_key(EVP_PKEY* key);
    static std::vector<uint8_t> serialize_private_key(EVP_PKEY* key);

    static EVP_PKEY_ptr deserialize_public_key(std::span<const uint8_t> data);
    static EVP_PKEY_ptr deserialize_private_key(std::span<const uint8_t> data);
};


class AES_GCM {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;

    struct EncryptResult {
        std::vector<uint8_t> ciphertext;
        std::array<uint8_t, IV_SIZE> iv;
        std::array<uint8_t, TAG_SIZE> tag;
    };

    static EncryptResult encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t> associated_data = {}
    );

    static EncryptResult encrypt_with_iv(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, IV_SIZE> iv,
        std::span<const uint8_t> associated_data = {}
    );

    static std::vector<uint8_t> decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, IV_SIZE> iv,
        std::span<const uint8_t, TAG_SIZE> tag,
        std::span<const uint8_t> associated_data = {}
    );
};

class ChaCha20Poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;

    struct EncryptResult {
        std::vector<uint8_t> ciphertext;
        std::array<uint8_t, NONCE_SIZE> nonce;
        std::array<uint8_t, TAG_SIZE> tag;
    };

    static EncryptResult encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t> associated_data = {}
    );

    static std::vector<uint8_t> decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, KEY_SIZE> key,
        std::span<const uint8_t, NONCE_SIZE> nonce,
        std::span<const uint8_t, TAG_SIZE> tag,
        std::span<const uint8_t> associated_data = {}
    );
};


class DigitalSignature {
public:
    static std::vector<uint8_t> sign_ed25519(
        std::span<const uint8_t> message,
        EVP_PKEY* private_key
    );

    static bool verify_ed25519(
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        EVP_PKEY* public_key
    );

    static std::vector<uint8_t> sign_ecdsa_p384(
        std::span<const uint8_t> message,
        EVP_PKEY* private_key
    );

    static bool verify_ecdsa_p384(
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        EVP_PKEY* public_key
    );

    static std::vector<uint8_t> sign_rsa_pss(
        std::span<const uint8_t> message,
        EVP_PKEY* private_key,
        const EVP_MD* hash_algo = EVP_sha384()
    );

    static bool verify_rsa_pss(
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        EVP_PKEY* public_key,
        const EVP_MD* hash_algo = EVP_sha384()
    );
};


class Hash {
public:
    static std::array<uint8_t, 32> sha256(std::span<const uint8_t> data);
    static std::array<uint8_t, 48> sha384(std::span<const uint8_t> data);
    static std::array<uint8_t, 64> sha512(std::span<const uint8_t> data);

    static std::vector<uint8_t> hmac_sha256(
        std::span<const uint8_t> key,
        std::span<const uint8_t> data
    );

    static std::vector<uint8_t> hmac_sha384(
        std::span<const uint8_t> key,
        std::span<const uint8_t> data
    );

    class Context {
    public:
        explicit Context(const EVP_MD* algorithm);
        ~Context() = default;

        Context(const Context&) = delete;
        Context& operator=(const Context&) = delete;
        Context(Context&&) = default;
        Context& operator=(Context&&) = default;

        void update(std::span<const uint8_t> data);
        std::vector<uint8_t> finalize();

    private:
        EVP_MD_CTX_ptr ctx_;
    };
};


class KeyDerivation {
public:
    static std::vector<uint8_t> hkdf_sha256(
        std::span<const uint8_t> input_key,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> info,
        size_t output_length
    );

    static std::vector<uint8_t> hkdf_sha384(
        std::span<const uint8_t> input_key,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> info,
        size_t output_length
    );

    static std::vector<uint8_t> pbkdf2_sha256(
        std::span<const uint8_t> password,
        std::span<const uint8_t> salt,
        int iterations,
        size_t output_length
    );

    static std::vector<uint8_t> scrypt(
        std::span<const uint8_t> password,
        std::span<const uint8_t> salt,
        uint64_t n,
        uint32_t r,
        uint32_t p,
        size_t output_length
    );
};


class Certificate {
public:
    explicit Certificate(X509_ptr cert);
    explicit Certificate(std::span<const uint8_t> der_data);
    static Certificate from_pem(const std::string& pem_data);

    X509* get() const { return cert_.get(); }
    std::vector<uint8_t> to_der() const;
    std::string to_pem() const;

    std::string get_subject() const;
    std::string get_issuer() const;
    std::string get_serial_number() const;
    int64_t get_not_before() const;
    int64_t get_not_after() const;

    EVP_PKEY_ptr get_public_key() const;
    std::array<uint8_t, 32> get_spki_pin_sha256() const;
    std::array<uint8_t, 48> get_spki_pin_sha384() const;

    bool verify_signature(EVP_PKEY* issuer_public_key) const;
    bool is_valid_at(int64_t timestamp) const;
    bool matches_hostname(const std::string& hostname) const;

private:
    X509_ptr cert_;
    std::vector<uint8_t> der_data_;
};

class CertificateStore {
public:
    CertificateStore();

    void add_certificate(const Certificate& cert);
    void add_ca_certificate(const Certificate& ca_cert);
    void load_system_cas();

    bool verify_chain(const std::vector<Certificate>& chain) const;
    bool verify_certificate(const Certificate& cert, const std::vector<Certificate>& intermediates = {}) const;

private:
    X509_STORE_ptr store_;
};


class SSLContext {
public:
    explicit SSLContext(const SSL_METHOD* method = TLS_client_method());

    void set_certificate_chain(const std::vector<Certificate>& chain);
    void set_private_key(EVP_PKEY* private_key);
    void set_ca_certificates(const std::vector<Certificate>& ca_certs);

    void set_cipher_list(const std::string& ciphers);
    void set_cipher_suites(const std::string& suites);

    void set_verify_mode(int mode);
    void set_verify_callback(std::function<bool(X509*, int)> callback);

    SSL_CTX* get() const { return ctx_.get(); }

private:
    SSL_CTX_ptr ctx_;
    std::function<bool(X509*, int)> verify_callback_;
};


namespace utils {

bool constant_time_equals(std::span<const uint8_t> a, std::span<const uint8_t> b);

void secure_clear(std::span<uint8_t> memory);
void secure_clear(void* ptr, size_t size);

std::string base64_encode(std::span<const uint8_t> data);
std::vector<uint8_t> base64_decode(const std::string& encoded);

std::string hex_encode(std::span<const uint8_t> data);
std::vector<uint8_t> hex_decode(const std::string& hex);

bool is_der_format(std::span<const uint8_t> data);
bool is_pem_format(const std::string& data);

std::vector<uint8_t> pem_to_der(const std::string& pem);
std::string der_to_pem(std::span<const uint8_t> der, const std::string& label);

}

}