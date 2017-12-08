#include "aes_openssl.h"
#include <openssl/aes.h>
#include <stdio.h>

static EVP_CIPHER_CTX en_ctx_struct, de_ctx_struct;
static EVP_CIPHER_CTX *en_ctx, *de_ctx;

int aes_create_key_and_iv(AES_KEY_INFO *key_info, AES_KEY_INIT_INFO *init_info)
{
    int i;

    if (!key_info)
        return -1;
    if (!init_info)
        return -1;

    /*
     * int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,
     *                       const unsigned char *salt,
     *                       const unsigned char *data, int datal, int count,
     *                       unsigned char *key,unsigned char *iv);
     *
     * salt should point to an 8-byte buffer or null
     */
    i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(),
            init_info->salt,
            init_info->key_data, init_info->key_data_len,
            init_info->nrounds,
            key_info->key, key_info->iv
            );
    if (i != AES_KEY_LEN_128_BIT)
    {
        printf("Key size is %d bytes - should be %d bytes\n", i, AES_KEY_LEN_128_BIT);
        return -1;
    }

    return 0;
}

int aes_init(AES_KEY_INFO *key_info)
{
    if (en_ctx || de_ctx)
    {
        printf("EVP contexts are already initialized! Can not initialize twice.\n");
        return -1;
    }

    en_ctx = &en_ctx_struct;
    de_ctx = &de_ctx_struct;

    /*
     *  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
     *      ENGINE *impl, unsigned char *key, unsigned char *iv);
     *
     * Set impl to NULL to use the default implementation.
     * key is the symmetric key
     * iv is the IV (Initialization vector)
     */
    EVP_CIPHER_CTX_init(en_ctx);
    EVP_EncryptInit_ex(en_ctx, EVP_aes_128_cbc(), NULL, key_info->key, key_info->iv);
    EVP_CIPHER_CTX_init(de_ctx);
    EVP_DecryptInit_ex(de_ctx, EVP_aes_128_cbc(), NULL, key_info->key, key_info->iv);

    return 0;
}

void aes_uninit(void)
{
    EVP_CIPHER_CTX_cleanup(en_ctx);
    EVP_CIPHER_CTX_cleanup(de_ctx);
    en_ctx = NULL;
    de_ctx = NULL;
}

// This will return a char * to a malloc'ed buffer of cipher text.
// The caller is responsible for freeing this buffer!
// It places the length of the ciphertext in ciphertext_len.
unsigned char *aes_encrypt(unsigned char *plaintext, int plaintext_len, int *ciphertext_len)
{
    // The resulting cipher text can range from 0 bytes to: input_length + cipher_block_size - 1
    // (not including the null terminator?).
    int ciphertext_max_len = plaintext_len + AES_BLOCK_SIZE;
    int update_encrypt_len = 0, final_encrypt_len = 0;
    unsigned char *ciphertext = malloc(ciphertext_max_len);
    unsigned char *ptr = NULL;

    // Not sure why, but this allows us to use the same context for multiple encryption cycles
    EVP_EncryptInit_ex(en_ctx, NULL, NULL, NULL, NULL);

    /*
     *  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
     *      int *outl, unsigned char *in, int inl);
     *
     * Encrypt 'in' and place it in 'out'.
     * Operates on 'inl' (input length) bytes and updates 'outl' accordingly.
     */
    EVP_EncryptUpdate(en_ctx, ciphertext, &update_encrypt_len, plaintext, plaintext_len);

    /*
     *  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
     *      int *outl);
     *
     * If padding is enabled, this encrypts any data that remains in a partial block.
     * Data is written to out.
     * The number of bytes written is placed in outl.
     */
    // Skip the portion of the buffer that was written to durign the 'Update' process
    ptr = ciphertext+update_encrypt_len;
    EVP_EncryptFinal_ex(en_ctx, ptr, &final_encrypt_len);

    *ciphertext_len = update_encrypt_len + final_encrypt_len;
    return ciphertext;
}

// This will return a char * to a malloc'ed buffer of decrypted cipher text.
// The caller is responsible for freeing this buffer!
// It places the length of the decrypted text in deryptedtext_len.
unsigned char *aes_decrypt(unsigned char *ciphertext, int ciphertext_len, int *decryptedtext_len)
{
    int decryptedtext_max_len = ciphertext_len + AES_BLOCK_SIZE;        // I think...
    int update_decrypt_len = 0, final_decrypt_len = 0;
    unsigned char *decryptedtext = malloc(decryptedtext_max_len);
    unsigned char *ptr;

    // Not sure why, but this allows us to use the same context for multiple dencryption cycles
    EVP_DecryptInit_ex(de_ctx, NULL, NULL, NULL, NULL);

    /*
     *  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
     *      int *outl, unsigned char *in, int inl);
     *
     * Decrypt 'in' and place it in 'out'.
     * Operates on 'inl' (input length) bytes and updates 'outl' accordingly.
     */
    EVP_DecryptUpdate(de_ctx, decryptedtext, &update_decrypt_len, ciphertext, ciphertext_len);

    /*  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
     *      int *outl);
     *
     * If padding is enabled, this decrypts any data that remains in a partial block.
     * Data is written to out.
     * The number of bytes written is placed in outl.
     */
    // Skip the portion of the buffer that was written to durign the 'Update' process
    ptr = decryptedtext + update_decrypt_len;
    EVP_DecryptFinal_ex(de_ctx, ptr, &final_decrypt_len);

    *decryptedtext_len = update_decrypt_len + final_decrypt_len;
    return decryptedtext;
}
