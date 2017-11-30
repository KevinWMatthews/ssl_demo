/* Demo code taken from:
 *      https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

// Returns 0 on success and -1 on failure
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt,
        EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx)
{
    int i, nrounds = 5;
    unsigned char key[17] = {0}, iv[17] = {0};  // Is null-termination necessary?

    // Generate key and initialization vector
    i = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    if (i != 16)
    {
        printf("Key size is %d bytes - should be 16 bytes (128 bits)\n", i);
        return -1;
    }

    /*
     *  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
     *      ENGINE *impl, unsigned char *key, unsigned char *iv);
     *
     * Set impl to NULL to use the default implementation.
     * key is the symmetric key
     * iv is the IV (Initialization vector)
     */
    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_128_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_128_cbc(), NULL, key, iv);

    return 0;
}

// This will return a char * to a malloc'ed buffer of cipher text.
// The caller is responsible for freeing this buffer!
// It places the length of the ciphertext in ciphertext_len.
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e_ctx, unsigned char *plaintext, int plaintext_len, int *ciphertext_len)
{
    // The resulting cipher text can range from 0 bytes to: input_length + cipher_block_size - 1
    // (not including the null terminator?).
    int ciphertext_max_len = plaintext_len + AES_BLOCK_SIZE;
    int update_encrypt_len = 0, final_encrypt_len = 0;
    unsigned char *ciphertext = malloc(ciphertext_max_len);
    unsigned char *ptr = NULL;

    // Not sure why, but this allows us to use the same context for multiple encryption cycles
    EVP_EncryptInit_ex(e_ctx, NULL, NULL, NULL, NULL);

    /*
     *  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
     *      int *outl, unsigned char *in, int inl);
     *
     * Encrypt 'in' and place it in 'out'.
     * Operates on 'inl' (input length) bytes and updates 'outl' accordingly.
     */
    EVP_EncryptUpdate(e_ctx, ciphertext, &update_encrypt_len, plaintext, plaintext_len);
    printf("encrypt update: %d\n", update_encrypt_len);

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
    EVP_EncryptFinal_ex(e_ctx, ptr, &final_encrypt_len);
    printf("encrypt final: %d\n", final_encrypt_len);

    *ciphertext_len = update_encrypt_len + final_encrypt_len;
    printf("encrypt total: %d\n", *ciphertext_len);
    return ciphertext;
}

// This will return a char * to a malloc'ed buffer of decrypted cipher text.
// The caller is responsible for freeing this buffer!
// It places the length of the decrypted text in deryptedtext_len.
unsigned char *aes_decrypt(EVP_CIPHER_CTX *d_ctx, unsigned char *ciphertext, int ciphertext_len, int *decryptedtext_len)
{
    int decryptedtext_max_len = ciphertext_len + AES_BLOCK_SIZE;        // I think...
    int update_decrypt_len = 0, final_decrypt_len = 0;
    unsigned char *decryptedtext = malloc(decryptedtext_max_len);
    unsigned char *ptr;

    // Not sure why, but this allows us to use the same context for multiple dencryption cycles
    EVP_DecryptInit_ex(d_ctx, NULL, NULL, NULL, NULL);

    /*
     *  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
     *      int *outl, unsigned char *in, int inl);
     *
     * Decrypt 'in' and place it in 'out'.
     * Operates on 'inl' (input length) bytes and updates 'outl' accordingly.
     */
    EVP_DecryptUpdate(d_ctx, decryptedtext, &update_decrypt_len, ciphertext, ciphertext_len);
    printf("decrypt update: %d\n", update_decrypt_len);

    /*  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm,
     *      int *outl);
     *
     * If padding is enabled, this decrypts any data that remains in a partial block.
     * Data is written to out.
     * The number of bytes written is placed in outl.
     */
    // Skip the portion of the buffer that was written to durign the 'Update' process
    ptr = decryptedtext + update_decrypt_len;
    EVP_DecryptFinal_ex(d_ctx, ptr, &final_decrypt_len);

    *decryptedtext_len = update_decrypt_len + final_decrypt_len;
    return decryptedtext;
}

int main(int argc, char **argv)
{
    EVP_CIPHER_CTX en_ctx, de_ctx;      // Encryption, decryption
    unsigned int salt[] = {12345, 54321};
    unsigned char *key_data;
    int key_data_len, i;
    char *input[] = {"a", "abcd", "this is a very long string!! It is so long. So very long.", NULL};

    if (argc <= 1)
    {
        printf("Must pass key_data as an argument!\n");
        return 0;
    }

    key_data = (unsigned char *)argv[1];
    key_data_len = strlen(argv[1]);

    if ( aes_init(key_data, key_data_len, (unsigned char *)&salt, &en_ctx, &de_ctx) < 0 )
    {
        printf("Couldn't initialize AES cipher\n");
        return -1;
    }

    for (i = 0; input[i]; i++)
    {
        unsigned char *plaintext = NULL, *ciphertext = NULL, *decryptedtext = NULL;
        int plaintext_len, ciphertext_len, decryptedtext_len;

        plaintext = (unsigned char *)input[i];
        // strlen does not include the null terminator
        // Apparently we pass this to the encrypt/decrypt functions so that they return a null-terminated string.
        plaintext_len = strlen(input[i])+1;

        ciphertext = aes_encrypt(&en_ctx, plaintext, plaintext_len, &ciphertext_len);
        decryptedtext = aes_decrypt(&de_ctx, ciphertext, ciphertext_len, &decryptedtext_len);

        if (strncmp((char *)plaintext, (char *)decryptedtext, plaintext_len))
            printf("FAIL: enc/dec failed for \"%s\"\n", plaintext);
        else
            printf("OK: enc/dec ok for \"%s\"\n", decryptedtext);

        if (ciphertext)
            free(ciphertext);
        if (decryptedtext)
            free(decryptedtext);
    }

    EVP_CIPHER_CTX_cleanup(&en_ctx);
    EVP_CIPHER_CTX_cleanup(&de_ctx);

    return 0;
}
