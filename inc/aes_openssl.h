#ifndef AES_OPENSSL_INCLUDED
#define AES_OPENSSL_INCLUDED

#include <openssl/evp.h>

/*
 * Create key and initialization vector from key data and a salt,
 * create and initialize EVP contexts.
 *
 * EVP contexts are handled entirely by the aes_openssl module,
 * but only a single context can be used at once.
 *
 * Returns 0 on success and -1 on failure.
 */
int aes_init(unsigned char *key_data, int key_data_len, unsigned char *salt);

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
