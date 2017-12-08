/* Demo code taken from:
 *      https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 */

#include <stdio.h>
#include <string.h>
#include "aes_openssl.h"

void hexprint(unsigned char *buffer, int buffer_len)
{
    int i;
    for (i = 0; i < buffer_len; i++)
        printf("%02x ", buffer[i]);
    printf("\n");
}

// buffer_len must include the null terminator
void decrypt_hex_buffer(unsigned char *buffer, int buffer_len)
{
    unsigned char *ciphertext = NULL, *decryptedtext = NULL;
    int ciphertext_len, decryptedtext_len;

    ciphertext = buffer;
    ciphertext_len = buffer_len;

    decryptedtext = aes_decrypt(ciphertext, ciphertext_len, &decryptedtext_len);

    printf("Encrypted data: ");
    hexprint(ciphertext, ciphertext_len);
    printf("Decrypted data: ");
    hexprint(decryptedtext, decryptedtext_len);

    if (decryptedtext)
        free(decryptedtext);
}

void encrypt_hex_buffer(unsigned char *buffer, int buffer_len)
{
    unsigned char *plaintext = NULL, *ciphertext = NULL;
    int plaintext_len, ciphertext_len;

    plaintext = buffer;
    plaintext_len = buffer_len;

    ciphertext = aes_encrypt(plaintext, plaintext_len, &ciphertext_len);

    printf("Original data:  ");
    hexprint(plaintext, plaintext_len);
    printf("Encrypted data: ");
    hexprint(ciphertext, ciphertext_len);

    if (ciphertext)
        free(ciphertext);
}

int run_aes_demo(int argc, char **argv)
{
    AES_KEY_INFO aes_key = {
        .key = {0},
        .iv = {0}
    };
    AES_KEY_INIT_INFO aes_key_init = {0};
    unsigned char salt[SALT_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    int i;

    aes_key_init.key_data = (unsigned char *)argv[1];
    aes_key_init.key_data_len = strlen(argv[1]);
    aes_key_init.salt = salt;
    aes_key_init.nrounds = 5;

    if ( aes_create_key_and_iv(&aes_key, &aes_key_init) < 0 )
    {
        printf("Failed to create AES key!\n");
        return 0;
    }
    char *input[] = {"a", "abcd", "this is a very long string!! It is so long. So very long.", NULL};

    if (argc <= 1)
    {
        printf("Must pass key_data as an argument!\n");
        return 0;
    }

    if ( aes_init(&aes_key) < 0 )
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

        ciphertext = aes_encrypt(plaintext, plaintext_len, &ciphertext_len);
        decryptedtext = aes_decrypt(ciphertext, ciphertext_len, &decryptedtext_len);

        if (strncmp((char *)plaintext, (char *)decryptedtext, plaintext_len))
            printf("FAIL: enc/dec failed for \"%s\"\n", plaintext);
        else
            printf("OK: enc/dec ok for \"%s\"\n", decryptedtext);

        if (ciphertext)
            free(ciphertext);
        if (decryptedtext)
            free(decryptedtext);
    }

    aes_uninit();

    return 0;
}

void decrypt_encrypt_demo(void)
{
    AES_KEY_INFO aes_key = {
        .key = {0},
        .iv = {0}
    };
    unsigned char hex_input[] = {0x4c, 0xbc, 0x48, 0xac, 0x6a, 0x99, 0x03, 0x07, 0x0b, 0x73, 0x66, 0x21, 0xec, 0xe3, 0xd9, 0xf7, 0};
    unsigned char hex_input2[] = {0x2c, 0x5f, 0xfc, 0x14, 0x0a, 0x21, 0xf8, 0x5c, 0xfd, 0x74, 0xa4, 0xb5, 0x25, 0xa5, 0x52, 0x3e};
    int i;

    for (i = 0; i < AES_KEY_LEN_128_BIT; i++)
        aes_key.key[i] = i;
    printf("AES Key: ");
    hexprint(aes_key.key, AES_KEY_LEN_128_BIT);

    aes_init(&aes_key);
    decrypt_hex_buffer( hex_input, sizeof(hex_input) );
    encrypt_hex_buffer( hex_input2, sizeof(hex_input2) );
    aes_uninit();
}

int main(int argc, char **argv)
{
    decrypt_encrypt_demo();
    return 0;
}
