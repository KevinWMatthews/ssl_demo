#ifndef AES_OPENSSL_INCLUDED
#define AES_OPENSSL_INCLUDED

#include <openssl/evp.h>

#define AES_KEY_LEN_128_BIT         16
#define SALT_LEN                    8
typedef struct AES_KEY_INFO
{
    unsigned char key[AES_KEY_LEN_128_BIT+1];       // AES key
    unsigned char iv[AES_KEY_LEN_128_BIT+1];        // Initialization vector
} AES_KEY_INFO;

typedef struct AES_KEY_INIT_INFO
{
    unsigned char *key_data;    // Random input used as a seed
    int key_data_len;
    unsigned char *salt;
    unsigned char nrounds;      // How many times to run the AES stuff. More is slower but more secure?
} AES_KEY_INIT_INFO;

/*
 * Initialize AES library.
 *
 * Initializes the EVP contexts.
 * EVP contexts are handled entirely by the aes_openssl module,
 * but only a single context can be used at once.
 *
 * Returns 0 on success and -1 on failure.
 */
int aes_init(AES_KEY_INFO *key_info);

/*
 * Create key and initialization vector from key data and a salt,
 * create and initialize EVP contexts.
 *
 * EVP contexts are handled entirely by the aes_openssl module,
 * but only a single context can be used at once.
 *
 * Returns 0 on success and -1 on failure.
 */

int aes_init_old(unsigned char *key_data, int key_data_len, unsigned char *salt);

/*
 * Create key and initialization vector from key data and a salt.
 *
 * Modifies the contents of key_info with the newly-created AES key and initialization vector.
 *
 * Returns 0 on success and -1 on failure.
 */
int aes_create_key_and_iv(AES_KEY_INFO *key_info, AES_KEY_INIT_INFO *init_info);

/*
 * Free all EVP contexts.
 */
void aes_uninit(void);

/*
 * Encrypt the plain text string, return a pointer to the cipher text, and write the length of the
 * cipher text string to ciphertext_len.
 * The caller is responsible for freeing the cipher text buffer!
 *
 *TODO Failure is unhandled.
 */
unsigned char *aes_encrypt(unsigned char *plaintext, int plaintext_len, int *ciphertext_len);

/*
 * Decrypt the cipher text string, return a pointer to the decrypted text, and write the length of the
 * decrypted text string to decryptedtext_len.
 * The caller is responsible for freeing the decrypted text buffer!
 *
 *TODO Failure is unhandled.
 */
unsigned char *aes_decrypt(unsigned char *ciphertext, int ciphertext_len, int *decryptedtext_len);

#endif
