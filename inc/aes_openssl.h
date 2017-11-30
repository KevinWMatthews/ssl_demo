#ifndef AES_OPENSSL_INCLUDED
#define AES_OPENSSL_INCLUDED

#include <openssl/evp.h>

int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
        EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e_ctx, unsigned char *plaintext,
        int plaintext_len, int *ciphertext_len);
unsigned char *aes_decrypt(EVP_CIPHER_CTX *d_ctx, unsigned char *ciphertext,
        int ciphertext_len, int *decryptedtext_len);

#endif
