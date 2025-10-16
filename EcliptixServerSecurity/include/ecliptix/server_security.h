#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>


#ifdef _WIN32
    #ifdef BUILDING_ECLIPTIX_SERVER
        #define ECLIPTIX_SERVER_API __declspec(dllexport)
    #else
        #define ECLIPTIX_SERVER_API __declspec(dllimport)
    #endif
    #define ECLIPTIX_SERVER_CALL __cdecl
#else
    #define ECLIPTIX_SERVER_API __attribute__((visibility("default")))
    #define ECLIPTIX_SERVER_CALL
#endif


typedef enum {
    ECLIPTIX_SERVER_SUCCESS = 0,
    ECLIPTIX_SERVER_ERR_NOT_INITIALIZED = -1,
    ECLIPTIX_SERVER_ERR_INVALID_PARAM = -3,
    ECLIPTIX_SERVER_ERR_MEMORY_ALLOCATION = -4,
    ECLIPTIX_SERVER_ERR_CRYPTO_FAILURE = -5,
    ECLIPTIX_SERVER_ERR_KEY_LOAD_FAILED = -6,
    ECLIPTIX_SERVER_ERR_SIGNATURE_FAILED = -11,
    ECLIPTIX_SERVER_ERR_DECRYPTION_FAILED = -12,
    ECLIPTIX_SERVER_ERR_ENCRYPTION_FAILED = -13,
    ECLIPTIX_SERVER_ERR_BUFFER_TOO_SMALL = -14,
    ECLIPTIX_SERVER_ERR_UNKNOWN = -99
} ecliptix_server_result_t;


#define ECLIPTIX_SERVER_ED25519_SIGNATURE_SIZE 64
#define ECLIPTIX_SERVER_RSA_MAX_PLAINTEXT_SIZE 214  // RSA-2048 with OAEP padding
#define ECLIPTIX_SERVER_RSA_CIPHERTEXT_SIZE 256     // RSA-2048 output size


ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_init(void);

ECLIPTIX_SERVER_API void ECLIPTIX_SERVER_CALL ecliptix_server_cleanup(void);

ECLIPTIX_SERVER_API const char* ECLIPTIX_SERVER_CALL ecliptix_server_get_error_message(void);


ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_encrypt_rsa(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const uint8_t* public_key_pem,
    size_t public_key_size,
    uint8_t* ciphertext,
    size_t* ciphertext_size
);

ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_decrypt_rsa(
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    uint8_t* plaintext,
    size_t* plaintext_size
);


ECLIPTIX_SERVER_API ecliptix_server_result_t ECLIPTIX_SERVER_CALL ecliptix_server_sign_ed25519(
    const uint8_t* message,
    size_t message_size,
    uint8_t* signature
);

#ifdef __cplusplus
}
#endif