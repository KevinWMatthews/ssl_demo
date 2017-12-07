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
void decrypt_hex_buffer(char *buffer, int buffer_len)
{
    unsigned char *plaintext = NULL, *ciphertext = NULL, *decryptedtext = NULL;
    int plaintext_len, ciphertext_len, decryptedtext_len;

    plaintext = (unsigned char *)buffer;
    plaintext_len = buffer_len;

    ciphertext = aes_encrypt(plaintext, plaintext_len, &ciphertext_len);
    decryptedtext = aes_decrypt(ciphertext, ciphertext_len, &decryptedtext_len);

    hexprint(plaintext, plaintext_len);
    hexprint(ciphertext, ciphertext_len);
    hexprint(decryptedtext, decryptedtext_len);

    if (ciphertext)
        free(ciphertext);
    if (decryptedtext)
        free(decryptedtext);
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

int main(int argc, char **argv)
{
    AES_KEY_INFO aes_key = {
        .key = {0},
        .iv = {0}
    };
    AES_KEY_INIT_INFO aes_key_init = {0};
    unsigned char salt[SALT_LEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

    aes_key_init.key_data = (unsigned char *)argv[1];
    aes_key_init.key_data_len = strlen(argv[1]);
    aes_key_init.salt = salt;
    aes_key_init.nrounds = 5;

    if ( aes_create_key_and_iv(&aes_key, &aes_key_init) < 0 )
    {
        printf("Failed to create AES key!\n");
        return 0;
    }

    aes_init(&aes_key);


    aes_uninit();

    return 0;
}
