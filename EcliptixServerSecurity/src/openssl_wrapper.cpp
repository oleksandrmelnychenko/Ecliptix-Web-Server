#include "internal/openssl_wrapper.hpp"
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <ctime>

#ifdef _WIN32
    #include <time.h>
    #define timegm _mkgmtime
#else
    #define _GNU_SOURCE
    #include <time.h>
#endif

namespace ecliptix::openssl {

namespace {
    using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
}


std::string get_error_string(unsigned long error_code) {
    if (error_code == 0) {
        return "No error";
    }

    char buffer[256];
    ERR_error_string_n(error_code, buffer, sizeof(buffer));
    return std::string(buffer);
}

std::string get_last_error() {
    unsigned long error = ERR_get_error();
    if (error == 0) {
        return "No error";
    }

    char buffer[256];
    ERR_error_string_n(error, buffer, sizeof(buffer));
    return std::string(buffer);
}

OpenSSLException::OpenSSLException(const std::string& message)
    : std::runtime_error(message) {
    error_code_ = ERR_get_error();
}

OpenSSLException::OpenSSLException(const std::string& operation, unsigned long error_code)
    : std::runtime_error(operation + ": " + get_error_string(error_code))
    , error_code_(error_code) {}

void clear_errors() {
    ERR_clear_error();
}


bool Library::initialized_ = false;

Library::Library() {
    if (initialized_) {
        return;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    if (RAND_poll() != 1) {
        throw OpenSSLException("Failed to initialize random number generator");
    }

    initialized_ = true;
}

Library::~Library() {
    if (initialized_) {
        EVP_cleanup();
        ERR_free_strings();
        CRYPTO_cleanup_all_ex_data();
        initialized_ = false;
    }
}

bool Library::is_initialized() {
    return initialized_;
}


void Random::bytes(std::span<uint8_t> buffer) {
    bytes(buffer.data(), buffer.size());
}

void Random::bytes(uint8_t* buffer, size_t size) {
    if (RAND_bytes(buffer, static_cast<int>(size)) != 1) {
        throw OpenSSLException("Random number generation failed");
    }
}

void Random::seed(std::span<const uint8_t> entropy) {
    RAND_seed(entropy.data(), static_cast<int>(entropy.size()));
}

int Random::status() {
    return RAND_status();
}


std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_ed25519() {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw OpenSSLException("Failed to create Ed25519 key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize Ed25519 key generation");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate Ed25519 key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    size_t public_key_len = 0;
    if (EVP_PKEY_get_raw_public_key(private_key.get(), nullptr, &public_key_len) != 1) {
        throw OpenSSLException("Failed to get Ed25519 public key length");
    }

    std::vector<uint8_t> public_key_raw(public_key_len);
    if (EVP_PKEY_get_raw_public_key(private_key.get(), public_key_raw.data(), &public_key_len) != 1) {
        throw OpenSSLException("Failed to extract Ed25519 public key");
    }

    EVP_PKEY_ptr public_key(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, public_key_raw.data(), public_key_len
    ));

    if (!public_key) {
        throw OpenSSLException("Failed to create Ed25519 public key object");
    }

    return {std::move(private_key), std::move(public_key)};
}

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_ecdsa_p384() {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw OpenSSLException("Failed to create ECDSA key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize ECDSA key generation");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp384r1) != 1) {
        throw OpenSSLException("Failed to set ECDSA curve to P-384");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate ECDSA P-384 key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    std::vector<uint8_t> public_key_der = serialize_public_key(private_key.get());
    EVP_PKEY_ptr public_key = deserialize_public_key(public_key_der);

    return {std::move(private_key), std::move(public_key)};
}

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_rsa(int bits) {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw OpenSSLException("Failed to create RSA key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize RSA key generation");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1) {
        throw OpenSSLException("Failed to set RSA key size");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate RSA key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    std::vector<uint8_t> public_key_der = serialize_public_key(private_key.get());
    EVP_PKEY_ptr public_key = deserialize_public_key(public_key_der);

    return {std::move(private_key), std::move(public_key)};
}

std::pair<EVP_PKEY_ptr, EVP_PKEY_ptr> KeyGenerator::generate_ecdh_x25519() {
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        throw OpenSSLException("Failed to create X25519 key context");
    }

    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw OpenSSLException("Failed to initialize X25519 key generation");
    }

    EVP_PKEY* private_key_raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &private_key_raw) != 1) {
        throw OpenSSLException("Failed to generate X25519 key pair");
    }

    EVP_PKEY_ptr private_key(private_key_raw);

    size_t public_key_len = 0;
    if (EVP_PKEY_get_raw_public_key(private_key.get(), nullptr, &public_key_len) != 1) {
        throw OpenSSLException("Failed to get X25519 public key length");
    }

    std::vector<uint8_t> public_key_raw(public_key_len);
    if (EVP_PKEY_get_raw_public_key(private_key.get(), public_key_raw.data(), &public_key_len) != 1) {
        throw OpenSSLException("Failed to extract X25519 public key");
    }

    EVP_PKEY_ptr public_key(EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, public_key_raw.data(), public_key_len
    ));

    if (!public_key) {
        throw OpenSSLException("Failed to create X25519 public key object");
    }

    return {std::move(private_key), std::move(public_key)};
}

std::vector<uint8_t> KeyGenerator::serialize_public_key(EVP_PKEY* key) {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    if (i2d_PUBKEY_bio(bio.get(), key) != 1) {
        throw OpenSSLException("Failed to serialize public key");
    }

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);

    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(buffer->data),
        reinterpret_cast<const uint8_t*>(buffer->data) + buffer->length
    );
}

std::vector<uint8_t> KeyGenerator::serialize_private_key(EVP_PKEY* key) {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    if (i2d_PrivateKey_bio(bio.get(), key) != 1) {
        throw OpenSSLException("Failed to serialize private key");
    }

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);

    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(buffer->data),
        reinterpret_cast<const uint8_t*>(buffer->data) + buffer->length
    );
}

EVP_PKEY_ptr KeyGenerator::deserialize_public_key(std::span<const uint8_t> data) {
    BIO_ptr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    EVP_PKEY* key = d2i_PUBKEY_bio(bio.get(), nullptr);
    if (!key) {
        throw OpenSSLException("Failed to deserialize public key");
    }

    return EVP_PKEY_ptr(key);
}

EVP_PKEY_ptr KeyGenerator::deserialize_private_key(std::span<const uint8_t> data) {
    BIO_ptr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!bio) {
        throw OpenSSLException("Failed to create memory BIO");
    }

    EVP_PKEY* key = d2i_PrivateKey_bio(bio.get(), nullptr);
    if (!key) {
        throw OpenSSLException("Failed to deserialize private key");
    }

    return EVP_PKEY_ptr(key);
}

// ============================================================================
// AES-GCM Implementation
// ============================================================================

AES_GCM::EncryptResult AES_GCM::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t> associated_data) {

    EncryptResult result;

    // Generate random IV
    Random::bytes(result.iv);

    result = encrypt_with_iv(plaintext, key, result.iv, associated_data);
    return result;
}

AES_GCM::EncryptResult AES_GCM::encrypt_with_iv(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, IV_SIZE> iv,
    std::span<const uint8_t> associated_data) {

    EncryptResult result;
    std::copy(iv.begin(), iv.end(), result.iv.begin());

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create cipher context");
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw OpenSSLException("Failed to initialize AES-256-GCM encryption");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
        throw OpenSSLException("Failed to set GCM IV length");
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw OpenSSLException("Failed to set key and IV");
    }

    // Set associated data if provided
    if (!associated_data.empty()) {
        int len;
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &len, associated_data.data(),
                             static_cast<int>(associated_data.size())) != 1) {
            throw OpenSSLException("Failed to set associated data");
        }
    }

    // Encrypt
    result.ciphertext.resize(plaintext.size());
    int len;
    if (EVP_EncryptUpdate(ctx.get(), result.ciphertext.data(), &len,
                         plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        throw OpenSSLException("Failed to encrypt data");
    }

    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(), result.ciphertext.data() + len, &len) != 1) {
        throw OpenSSLException("Failed to finalize encryption");
    }

    ciphertext_len += len;
    result.ciphertext.resize(static_cast<size_t>(ciphertext_len));

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, result.tag.data()) != 1) {
        throw OpenSSLException("Failed to get authentication tag");
    }

    return result;
}

std::vector<uint8_t> AES_GCM::decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t, KEY_SIZE> key,
    std::span<const uint8_t, IV_SIZE> iv,
    std::span<const uint8_t, TAG_SIZE> tag,
    std::span<const uint8_t> associated_data) {

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create cipher context");
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw OpenSSLException("Failed to initialize AES-256-GCM decryption");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
        throw OpenSSLException("Failed to set GCM IV length");
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1) {
        throw OpenSSLException("Failed to set key and IV");
    }

    // Set associated data if provided
    if (!associated_data.empty()) {
        int len;
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, associated_data.data(),
                             static_cast<int>(associated_data.size())) != 1) {
            throw OpenSSLException("Failed to set associated data");
        }
    }

    // Decrypt
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                         ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
        throw OpenSSLException("Failed to decrypt data");
    }

    int plaintext_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                           const_cast<uint8_t*>(tag.data())) != 1) {
        throw OpenSSLException("Failed to set authentication tag");
    }

    // Finalize decryption and verify tag
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
        throw OpenSSLException("Authentication verification failed");
    }

    plaintext_len += len;
    plaintext.resize(static_cast<size_t>(plaintext_len));

    return plaintext;
}

// ============================================================================
// Digital Signatures
// ============================================================================

std::vector<uint8_t> DigitalSignature::sign_ed25519(
    std::span<const uint8_t> message,
    EVP_PKEY* private_key) {

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create signing context");
    }

    if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, private_key) != 1) {
        throw OpenSSLException("Failed to initialize Ed25519 signing");
    }

    // Get signature length
    size_t signature_len = 0;
    if (EVP_DigestSign(ctx.get(), nullptr, &signature_len, message.data(), message.size()) != 1) {
        throw OpenSSLException("Failed to get Ed25519 signature length");
    }

    // Create signature
    std::vector<uint8_t> signature(signature_len);
    if (EVP_DigestSign(ctx.get(), signature.data(), &signature_len,
                      message.data(), message.size()) != 1) {
        throw OpenSSLException("Failed to create Ed25519 signature");
    }

    signature.resize(signature_len);
    return signature;
}

bool DigitalSignature::verify_ed25519(
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature,
    EVP_PKEY* public_key) {

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) {
        throw OpenSSLException("Failed to create verification context");
    }

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, public_key) != 1) {
        throw OpenSSLException("Failed to initialize Ed25519 verification");
    }

    int result = EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                 message.data(), message.size());

    if (result == 1) {
        return true;  // Signature valid
    } else if (result == 0) {
        return false; // Signature invalid
    } else {
        throw OpenSSLException("Ed25519 signature verification failed");
    }
}

// ============================================================================
// Hash Functions
// ============================================================================

std::array<uint8_t, 32> Hash::sha256(std::span<const uint8_t> data) {
    std::array<uint8_t, 32> result;

    if (SHA256(data.data(), data.size(), result.data()) == nullptr) {
        throw OpenSSLException("SHA-256 hash computation failed");
    }

    return result;
}

std::array<uint8_t, 48> Hash::sha384(std::span<const uint8_t> data) {
    std::array<uint8_t, 48> result;

    if (SHA384(data.data(), data.size(), result.data()) == nullptr) {
        throw OpenSSLException("SHA-384 hash computation failed");
    }

    return result;
}

std::array<uint8_t, 64> Hash::sha512(std::span<const uint8_t> data) {
    std::array<uint8_t, 64> result;

    if (SHA512(data.data(), data.size(), result.data()) == nullptr) {
        throw OpenSSLException("SHA-512 hash computation failed");
    }

    return result;
}

Hash::Context::Context(const EVP_MD* algorithm)
    : ctx_(EVP_MD_CTX_new()) {
    if (!ctx_) {
        throw OpenSSLException("Failed to create hash context");
    }

    if (EVP_DigestInit_ex(ctx_.get(), algorithm, nullptr) != 1) {
        throw OpenSSLException("Failed to initialize hash context");
    }
}

void Hash::Context::update(std::span<const uint8_t> data) {
    if (EVP_DigestUpdate(ctx_.get(), data.data(), data.size()) != 1) {
        throw OpenSSLException("Failed to update hash context");
    }
}

std::vector<uint8_t> Hash::Context::finalize() {
    unsigned int digest_len = 0;
    std::vector<uint8_t> digest(static_cast<size_t>(EVP_MD_size(EVP_MD_CTX_md(ctx_.get()))));

    if (EVP_DigestFinal_ex(ctx_.get(), digest.data(), &digest_len) != 1) {
        throw OpenSSLException("Failed to finalize hash");
    }

    digest.resize(digest_len);
    return digest;
}

// ============================================================================
// Certificate Implementation
// ============================================================================

Certificate::Certificate(X509_ptr cert) : cert_(std::move(cert)) {}

Certificate::Certificate(std::span<const uint8_t> der_data) {
    const uint8_t* data = der_data.data();
    cert_.reset(d2i_X509(nullptr, &data, static_cast<long>(der_data.size())));
    if (!cert_) {
        throw OpenSSLException("Failed to parse DER certificate data");
    }
}

Certificate Certificate::from_pem(const std::string& pem_data) {
    BIO_ptr bio(BIO_new_mem_buf(pem_data.data(), static_cast<int>(pem_data.size())));
    if (!bio) {
        throw OpenSSLException("Failed to create BIO for PEM data");
    }

    X509* cert_raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
    if (!cert_raw) {
        throw OpenSSLException("Failed to parse PEM certificate");
    }

    return Certificate(X509_ptr(cert_raw));
}

std::vector<uint8_t> Certificate::to_der() const {
    uint8_t* der_data = nullptr;
    int der_len = i2d_X509(cert_.get(), &der_data);
    if (der_len < 0 || !der_data) {
        throw OpenSSLException("Failed to encode certificate to DER");
    }

    std::vector<uint8_t> result(der_data, der_data + der_len);
    OPENSSL_free(der_data);
    return result;
}

std::string Certificate::to_pem() const {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        throw OpenSSLException("Failed to create BIO for PEM output");
    }

    if (PEM_write_bio_X509(bio.get(), cert_.get()) != 1) {
        throw OpenSSLException("Failed to write certificate to PEM");
    }

    char* pem_data;
    long pem_len = BIO_get_mem_data(bio.get(), &pem_data);
    return std::string(pem_data, static_cast<size_t>(pem_len));
}

std::string Certificate::get_subject() const {
    X509_NAME* name = X509_get_subject_name(cert_.get());
    if (!name) {
        throw OpenSSLException("Failed to get certificate subject");
    }

    char* str = X509_NAME_oneline(name, nullptr, 0);
    if (!str) {
        throw OpenSSLException("Failed to convert subject name to string");
    }

    std::string result(str);
    OPENSSL_free(str);
    return result;
}

std::string Certificate::get_issuer() const {
    X509_NAME* name = X509_get_issuer_name(cert_.get());
    if (!name) {
        throw OpenSSLException("Failed to get certificate issuer");
    }

    char* str = X509_NAME_oneline(name, nullptr, 0);
    if (!str) {
        throw OpenSSLException("Failed to convert issuer name to string");
    }

    std::string result(str);
    OPENSSL_free(str);
    return result;
}

std::string Certificate::get_serial_number() const {
    const ASN1_INTEGER* serial = X509_get_serialNumber(cert_.get());
    if (!serial) {
        throw OpenSSLException("Failed to get certificate serial number");
    }

    BIGNUM_ptr bn(ASN1_INTEGER_to_BN(serial, nullptr));
    if (!bn) {
        throw OpenSSLException("Failed to convert serial number to BIGNUM");
    }

    char* str = BN_bn2hex(bn.get());
    if (!str) {
        throw OpenSSLException("Failed to convert serial number to hex string");
    }

    std::string result(str);
    OPENSSL_free(str);
    return result;
}

int64_t Certificate::get_not_before() const {
    const ASN1_TIME* not_before = X509_get0_notBefore(cert_.get());
    if (!not_before) {
        throw OpenSSLException("Failed to get certificate not_before time");
    }

    struct tm tm_time;
    if (ASN1_TIME_to_tm(not_before, &tm_time) != 1) {
        throw OpenSSLException("Failed to convert not_before time");
    }

    return static_cast<int64_t>(timegm(&tm_time));
}

int64_t Certificate::get_not_after() const {
    const ASN1_TIME* not_after = X509_get0_notAfter(cert_.get());
    if (!not_after) {
        throw OpenSSLException("Failed to get certificate not_after time");
    }

    struct tm tm_time;
    if (ASN1_TIME_to_tm(not_after, &tm_time) != 1) {
        throw OpenSSLException("Failed to convert not_after time");
    }

    return static_cast<int64_t>(timegm(&tm_time));
}

bool Certificate::is_valid_at(int64_t timestamp) const {
    int64_t not_before = get_not_before();
    int64_t not_after = get_not_after();
    return timestamp >= not_before && timestamp <= not_after;
}

bool Certificate::matches_hostname(const std::string& hostname) const {
    int result = X509_check_host(cert_.get(), hostname.c_str(), hostname.length(), 0, nullptr);
    return result == 1;
}

EVP_PKEY_ptr Certificate::get_public_key() const {
    EVP_PKEY* pkey = X509_get_pubkey(cert_.get());
    if (!pkey) {
        throw OpenSSLException("Failed to extract public key from certificate");
    }
    return EVP_PKEY_ptr(pkey);
}

std::array<uint8_t, 32> Certificate::get_spki_pin_sha256() const {
    // Get the SubjectPublicKeyInfo structure
    X509_PUBKEY* spki = X509_get_X509_PUBKEY(cert_.get());
    if (!spki) {
        throw OpenSSLException("Failed to get SubjectPublicKeyInfo");
    }

    // Encode SPKI to DER
    uint8_t* spki_der = nullptr;
    int spki_len = i2d_X509_PUBKEY(spki, &spki_der);
    if (spki_len < 0 || !spki_der) {
        throw OpenSSLException("Failed to encode SPKI to DER");
    }

    // Compute SHA-256 hash
    std::array<uint8_t, 32> hash;
    unsigned int hash_len = 0;

    if (EVP_Digest(spki_der, static_cast<size_t>(spki_len), hash.data(), &hash_len, EVP_sha256(), nullptr) != 1) {
        OPENSSL_free(spki_der);
        throw OpenSSLException("Failed to compute SHA-256 hash of SPKI");
    }

    OPENSSL_free(spki_der);

    if (hash_len != 32) {
        throw OpenSSLException("Unexpected SHA-256 hash length");
    }

    return hash;
}

std::array<uint8_t, 48> Certificate::get_spki_pin_sha384() const {
    // Get the SubjectPublicKeyInfo structure
    X509_PUBKEY* spki = X509_get_X509_PUBKEY(cert_.get());
    if (!spki) {
        throw OpenSSLException("Failed to get SubjectPublicKeyInfo");
    }

    // Encode SPKI to DER
    uint8_t* spki_der = nullptr;
    int spki_len = i2d_X509_PUBKEY(spki, &spki_der);
    if (spki_len < 0 || !spki_der) {
        throw OpenSSLException("Failed to encode SPKI to DER");
    }

    // Compute SHA-384 hash
    std::array<uint8_t, 48> hash;
    unsigned int hash_len = 0;

    if (EVP_Digest(spki_der, static_cast<size_t>(spki_len), hash.data(), &hash_len, EVP_sha384(), nullptr) != 1) {
        OPENSSL_free(spki_der);
        throw OpenSSLException("Failed to compute SHA-384 hash of SPKI");
    }

    OPENSSL_free(spki_der);

    if (hash_len != 48) {
        throw OpenSSLException("Unexpected SHA-384 hash length");
    }

    return hash;
}

// ============================================================================
// Key Derivation
// ============================================================================

std::vector<uint8_t> KeyDerivation::hkdf_sha384(
    std::span<const uint8_t> input_key,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_length) {

    EVP_KDF_CTX_ptr ctx(EVP_KDF_CTX_new(EVP_KDF_fetch(nullptr, "HKDF", nullptr)));
    if (!ctx) {
        throw OpenSSLException("Failed to create HKDF context");
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>("SHA384"), 0),
        OSSL_PARAM_construct_octet_string("key", const_cast<uint8_t*>(input_key.data()), input_key.size()),
        OSSL_PARAM_construct_octet_string("salt", const_cast<uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_octet_string("info", const_cast<uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_CTX_set_params(ctx.get(), params) != 1) {
        throw OpenSSLException("Failed to set HKDF parameters");
    }

    std::vector<uint8_t> output(output_length);
    if (EVP_KDF_derive(ctx.get(), output.data(), output.size(), nullptr) != 1) {
        throw OpenSSLException("HKDF key derivation failed");
    }

    return output;
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace utils {

bool constant_time_equals(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    if (a.size() != b.size()) {
        return false;
    }

    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

void secure_clear(std::span<uint8_t> memory) {
    OPENSSL_cleanse(memory.data(), memory.size());
}

void secure_clear(void* ptr, size_t size) {
    OPENSSL_cleanse(ptr, size);
}

std::string base64_encode(std::span<const uint8_t> data) {
    BIO_ptr bio(BIO_new(BIO_s_mem()));
    BIO_ptr b64(BIO_new(BIO_f_base64()));

    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    bio.reset(BIO_push(b64.release(), bio.release()));

    BIO_write(bio.get(), data.data(), static_cast<int>(data.size()));
    BIO_flush(bio.get());

    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);

    return std::string(buffer->data, buffer->length);
}

} // namespace utils

} // namespace ecliptix::openssl