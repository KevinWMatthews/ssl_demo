#include "aes_openssl.h"
#include <openssl/aes.h>
#include <openssl/err.h>
#include <stdio.h>

#define BUGFIX_EVP_DECRYPT_UPDATE

static void hexprint(unsigned char *buffer, int buffer_len)
{
    int i;
    for (i = 0; i < buffer_len; i++)
        printf("%02x ", buffer[i]);
    printf("\n");
}

// AES_BLOCK_SIZE is 16 bytes and is defined in openssl/aes.h

//TODO we can rewrite this to use a single context, I think.
// See EVP_CipherInit_ex(), etc.

typedef enum
{
    EVP_FALURE  = 0,
    EVP_SUCCESS = 1
} OPENSSL_EVP_ERROR;

static EVP_CIPHER_CTX en_ctx_struct, de_ctx_struct;
static EVP_CIPHER_CTX *en_ctx, *de_ctx;

static void aes_print_errors(void)
{
    /*
     * void ERR_print_errors_fp(FILE *fp);
     *
     * Prints the error strings for all errors that OpenSSL has recorded.
     * Empties the error queue.
     *
     * Error messages are of the form:
     *  [pid]:error:[error code]:[library name]:[function name]:[reason string]:[file name]:[line]:[optional text message]
     *
     * Error messages will be translated to human-readable form if ERR_load_crypto_strings() is called.
     */
    ERR_print_errors_fp(stderr);
}

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
        return AES_FAILURE;
    }

    return AES_SUCCESS;
}

int aes_init(AES_KEY_INFO *key_info)
{
    int ret;

    if (en_ctx || de_ctx)
    {
        printf("EVP contexts are already initialized! Can not initialize twice.\n");
        return AES_FAILURE;
    }

    /*
     * void ERR_load_crypto_strings(void);
     *
     * Registers the error strings for all of OpenSSL's libcrypto functions.
     * This causes ERR_print_errors_fp to print human-readable output.
     */
    ERR_load_crypto_strings();

    en_ctx = &en_ctx_struct;
    de_ctx = &de_ctx_struct;

    /*
     * void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);
     *
     * Initializes cipher contex. Apparently it can not fail.
     */
    EVP_CIPHER_CTX_init(en_ctx);

    /*
     *  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
     *      ENGINE *impl, unsigned char *key, unsigned char *iv);
     *
     * Set impl to NULL to use the default implementation.
     * key is the symmetric key
     * iv is the IV (Initialization Vector)
     *
     * Returns 1 on success and 0 on failure.
     */
    ret = EVP_EncryptInit_ex(en_ctx, EVP_aes_128_cbc(), NULL, key_info->key, key_info->iv);
    if (ret != EVP_SUCCESS)
    {
        printf("%s: Error during EncryptInit\n", __func__);
        aes_print_errors();
        return AES_FAILURE;
    }

    EVP_CIPHER_CTX_init(de_ctx);
    ret = EVP_DecryptInit_ex(de_ctx, EVP_aes_128_cbc(), NULL, key_info->key, key_info->iv);
    if (ret != EVP_SUCCESS)
    {
        printf("%s: Error during DecryptInit\n", __func__);
        aes_print_errors();
        return AES_FAILURE;
    }

    return AES_SUCCESS;
}

int aes_uninit(void)
{
    int ret_en, ret_de;

    ret_en = EVP_CIPHER_CTX_cleanup(en_ctx);
    en_ctx = NULL;
    if (ret_en != EVP_SUCCESS)
    {
        printf("%s: Error during encrypt cleanup\n", __func__);
        aes_print_errors();
    }

    ret_de = EVP_CIPHER_CTX_cleanup(de_ctx);
    de_ctx = NULL;
    if (ret_de != EVP_SUCCESS)
    {
        printf("%s: Error during decrypt cleanup\n", __func__);
        aes_print_errors();
    }

    /*
     * void ERR_free_strings(void);
     *
     * Free all OpenSSL error strings
     */
    ERR_free_strings();

    if (ret_en != EVP_SUCCESS)
        return AES_FAILURE;
    if (ret_de != EVP_SUCCESS)
        return AES_FAILURE;

    return AES_SUCCESS;
}

unsigned char *aes_encrypt(unsigned char *plaintext, int plaintext_len, int *ciphertext_len)
{
    int ciphertext_max_len = 0;
    int update_len = 0, final_len = 0;
    unsigned char *ciphertext = NULL;
    unsigned char *ptr = NULL;
    int ret;

    // The resulting encrypted text can range from 0 bytes to: input_length + cipher_block_size - 1
    // This is true, though in my experience cipher text is always padded/expanded to be
    // written in increments of AES_BLOCK_SIZE.
    ciphertext_max_len = plaintext_len + AES_BLOCK_SIZE - 1;
    ciphertext = calloc( ciphertext_max_len, sizeof(*ciphertext) );
    if (ciphertext == NULL)
        return NULL;        // Well, now you're in deep.

    // Not sure why, but this allows us to use the same context for multiple encryption cycles.
    // It fails if I don't call this.
    ret = EVP_EncryptInit_ex(en_ctx, NULL, NULL, NULL, NULL);
    if (ret != EVP_SUCCESS)
    {
        printf("%s: Error during Init\n", __func__);
        aes_print_errors();
        if (ciphertext)
            free(ciphertext);
        return NULL;
    }

    /*
     * EncryptUpdate() reads input data in multiples of AES_BLOCK_SIZE
     * and produces a corresponding amount of encrypted output.
     *
     * If the input data *is not* a multiple of AES_BLOCK_SIZE, some input data remains to be
     * encrypted after the call to EncryptUpdate(). A call to EncryptFinal() will read the
     * remaining input data and produce one more block (AES_BLOCK_SIZE) of encrypted data.
     *
     * If the input data *is* a multiple of AES_BLOCK_SIZE (there is no remaining data),
     * do not call EncryptFinal()! EncryptUpdate() will encrypt the the entire input.
     * A call to EncryptFinal() will read and encrypt a block of garbage.
     *
     * The encryption algorithms in EncryptFinal() always produce output in blocks of AES_BLOCK_SIZE,
     * regardless of input size. This is a feature of AES encryption.
     */

    /*
     *  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
     *      int *outl, unsigned char *in, int inl);
     *
     * Encrypt 'in' and place it in 'out'.
     * Operates on 'inl' (input length) bytes and updates 'outl' accordingly.
     *
     * Reads and encrypts data in multiples of AES_BLOCK_SIZE; no more, no less.
     * The block size (for AES encryption, at least) is 16 bytes.
     */
    ret = EVP_EncryptUpdate(en_ctx, ciphertext, &update_len, plaintext, plaintext_len);
    if (ret != EVP_SUCCESS)
    {
        printf("%s: Error during Update\n", __func__);
        aes_print_errors();
        if (ciphertext)
            free(ciphertext);
        return NULL;
    }

    if (update_len < plaintext_len)
    {
        // Some data remains to be read and encrypted.
        // Call EncryptFinal() to do this.

        // Skip the portion of the buffer that was written to during the 'Update' call.
        ptr = ciphertext + update_len;

        /*
         *  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
         *      int *outl);
         *
         * If padding is enabled and data remains in a partial block, this encrypts the remaining data.
         * If padding is enabled and no data remains in a partial block, this produces garbage (!).
         * If padding is not enabled and a partial block remains, this throws an error.
         *
         * Data is written to 'out'.
         * The number of bytes written is writte to 'outl'.
         */
        ret = EVP_EncryptFinal_ex(en_ctx, ptr, &final_len);
        if (ret != EVP_SUCCESS)
        {
            printf("%s: Error during Final\n", __func__);
            aes_print_errors();
            if (ciphertext)
                free(ciphertext);
            return NULL;
        }
    }
    else if (update_len == plaintext_len)
    {
        // All data has been read and encrypted by EncryptUpdate().
        // A call to EncryptFinal() will read, encrypt, and produce an extra block of garbage!
        final_len = 0;
    }
    else
    {
        // This should never happen - EncryptUpdate() shouldn't read more than its input length.
        printf("%s: Encryption overflow\n", __func__);
        if (ciphertext)
            free(ciphertext);
        return NULL;
    }

    *ciphertext_len = update_len + final_len;
    return ciphertext;
}

unsigned char *aes_decrypt(unsigned char *ciphertext, int ciphertext_len, int *plaintext_len)
{
    int plaintext_max_len = 0;
    int update_len = 0, final_len = 0;
    unsigned char *plaintext = NULL;
    unsigned char *ptr;
    int ret;

    // The resulting decrypted text can range from 0 bytes to: input_length + cipher_block_size
    plaintext_max_len = ciphertext_len + AES_BLOCK_SIZE;
    plaintext = calloc( plaintext_max_len, sizeof(*plaintext) );
    if (plaintext == NULL)
        return NULL;        // Have fun.

    // Not sure why, but this allows us to use the same context for multiple decryption cycles
    ret = EVP_DecryptInit_ex(de_ctx, NULL, NULL, NULL, NULL);
    if (ret != EVP_SUCCESS)
    {
        printf("%s: Error during Init\n", __func__);
        aes_print_errors();
        if (plaintext)
            free(plaintext);
        return NULL;
    }

    /*
     * DecryptUpdate() reads encrypted input data and produces output in multiples of AES_BLOCK_SIZE.
     *
     * If the original unencrypted data *is not* a multiple of AES_BLOCK_SIZE,
     * some input data remains to be decrypted after the call to DecryptUpdate().
     * A call to DecryptFinal() will unencrypt the remaining data.
     *
     * If the original unencrypted data *is* a multiple of AES_BLOCK_SIZE,
     * a cal to DecryptFinal() is unnecessary but not harmful.
     */

    /*
     *  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
     *      int *outl, unsigned char *in, int inl);
     *
     * Reads and decryptes data in multiples of AES_BLOCK_SIZE.
     * Produces output in multiples of AES_BLOCK_SIZE.
     * Avoid reading beyond 'outl'.
     *
     * Decrypt 'in' and place it in 'out'.
     * Operates on 'inl' (input length) bytes and updates 'outl' accordingly.
     */
    ret = EVP_DecryptUpdate(de_ctx, plaintext, &update_len, ciphertext, ciphertext_len);
    if (ret != EVP_SUCCESS)
    {
        printf("%s: Error during Update\n", __func__);
        aes_print_errors();
        if (plaintext)
            free(plaintext);
        return NULL;
    }

    // Skip the portion of the buffer that was decrypted the 'Update' process
    ptr = plaintext + update_len;

    /*  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
     *      int *outl);
     *
     * If padding is enabled and data remains in a partial block, this decrypts the remaining data.
     * If padding is enabled and no data remains in a partial block, this throws an error.
     * If padding is not enabled and a partial block remains, this throws an error.
     *
     * Data is written to 'out'.
     * The number of bytes written is written to 'outl'.
     */
    ret = EVP_DecryptFinal_ex(de_ctx, ptr+16, &final_len);
    if (ret != EVP_SUCCESS)
    {
        printf("%s: Error during Final:\n", __func__);
        aes_print_errors();
#ifdef BUGFIX_EVP_DECRYPT_UPDATE
        /*
         * There is a bug in OpenSSL 1.0.1f 6 Jan 2014 (or I am using the library improperly):
         *  If the original input text is a multiple of AES_BLOCK_SIZE (16 bytes),
         *  EVP_DecryptUpdate() under-reports the number of decrypted bytes by 16.
         *  In this case there is no data remaining in a partial block so
         *  EVP_DecryptFinal() yields a 'outl' of zero.
         */
        printf("%s: Ignoring error in DecryptFinal - bug workaround\n", __func__);
        if (final_len == 0)
            update_len += 16;
#else
        if (plaintext)
            free(plaintext);
        return NULL;
#endif
    }

    *plaintext_len = update_len + final_len;

    return plaintext;
}
