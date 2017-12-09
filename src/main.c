/* Demo code taken from:
 *      https://github.com/saju/misc/blob/master/misc/openssl_aes.c
 */

#include <stdio.h>
#include <string.h>
#include "aes_openssl.h"
#include "tools.h"

#if 0
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
    printf("buffer: ");
    hexprint(plaintext, plaintext_len);
    printf("buffer len: %d\n", buffer_len);

    // ciphertext = aes_encrypt(plaintext, plaintext_len, &ciphertext_len);

    // printf("Original data:  ");
    // hexprint(plaintext, plaintext_len);
    // printf("Encrypted data: ");
    // hexprint(ciphertext, ciphertext_len);

    // if (ciphertext)
        // free(ciphertext);
}
#endif

#if 0
// This demo if based on the original example.
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
#endif

// 16 bytes (AES_KEY_LEN_128_BIT) plus a null terminator
#define SAMPLE_AES_KEY  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0
#define SAMPLE_IV       0

// Sample plaintext data to be encrypted
#define HEX_STRING      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0
#define HEX_STRING_SHORT    0x00, 0x01, 0x02, 0x03
#define HEX_STRING_LONG     0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0, 0

#define TEXT_STRING         "abcd"
// This is a demo that I wrote showing how to use the aes_openssl wrapper module.
void demo_encrypt_decrypt(void)
{
    // Create struct for AES key
    AES_KEY_INFO aes_key = {
        // .key = {SAMPLE_AES_KEY},
        .key = {0},
        .iv = {SAMPLE_IV}
    };

    // Create text buffers
    // unsigned char plaintext[] = {HEX_STRING_SHORT};
    unsigned char plaintext[16] = {0};
    int plaintext_len = sizeof(plaintext);
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    unsigned char *decryptedtext = NULL;
    int decryptedtext_len = 0;

    // Initialize
    aes_init(&aes_key);

    printf("AES Key:\t\t");
    hexprint(aes_key.key, AES_KEY_LEN_128_BIT);
    printf("\n");

    printf("\t\t\t01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33\n");
    printf("\t\t\t--------------------------------------------------------------------------------------------------\n");
    printf("Plain (%d):\t\t", plaintext_len);
    hexprint(plaintext, plaintext_len);

    // Encrypt and decrypt
    ciphertext = aes_encrypt(plaintext, plaintext_len, &ciphertext_len);
    if (!ciphertext)
        printf("Error encrypting!\n");

    printf("Encrypted (%d):\t\t", ciphertext_len);
    hexprint(ciphertext, ciphertext_len);
    printf("\n");

    decryptedtext = aes_decrypt(ciphertext, ciphertext_len, &decryptedtext_len);
    if (!decryptedtext)
        printf("Error decrypting!\n");

    // Print results
    printf("Decrypted (%d):\t\t", decryptedtext_len);
    hexprint(decryptedtext, decryptedtext_len);

    // Teardown
    aes_uninit();
    if (ciphertext)
        free(ciphertext);
    if (decryptedtext)
        free(decryptedtext);
}

#if 0
void demo_mifare_plus_x(void)
{
    unsigned char rnd_b[] = {0x08, 0x2E, 0xC5, 0xDB, 0x5B, 0x11, 0xFF, 0xEE, 0xFB, 0x21, 0x4F, 0x26, 0x93, 0x66, 0x09, 0xDE, 0};
    int rnd_b_len = sizeof(rnd_b);

    unsigned char *E_rnd_b = NULL;
    int E_rnd_b_len = 0;

    unsigned char expected_E_rnd_b[] = {0xE2, 0x76, 0x3C, 0xAA, 0x9E, 0xF7, 0x9C, 0xC0, 0x63, 0xA1, 0xC6, 0x42, 0xAD, 0x56, 0x39, 0xC5, 0};

    AES_KEY_INFO aes_key = {
        .key = {0xA3, 0x81, 0x52, 0xC9, 0x03, 0x55, 0xCC, 0x63, 0xAC, 0x6E, 0x97, 0xA3, 0x99, 0x80, 0x7b, 0x59, 0},
        .iv = {0}
    };

    aes_init(&aes_key);
    E_rnd_b = aes_encrypt( rnd_b, rnd_b_len, &E_rnd_b_len );
    printf("Expected: ");
    hexprint(expected_E_rnd_b, 16);
    printf("Actual:   ");
    hexprint(E_rnd_b, 16);

    unsigned char rnd_a[] = {0xBA, 0x0D, 0xB8, 0x20, 0x1E, 0x89, 0x7F, 0x8A, 0x5C, 0xD2, 0xAF, 0x32, 0x7A, 0xD4, 0xB5, 0xEC, 0};

    unsigned char rnd_b_prime[17] = {0};
    unsigned char expected_rnd_b_prime[] = {0x2E, 0xC5, 0xDB, 0x5B, 0x11, 0xFF, 0xEE, 0xFB, 0x21, 0x4F, 0x26, 0x93, 0x66, 0x09, 0xDE, 0x08, 0};

    // RndA | RndB'
    unsigned char challenge_rsp[] = {0xBE, 0xCD, 0xFB, 0x7B, 0x1F, 0xFF, 0xFF, 0xFB, 0x7D, 0xDF, 0xAF, 0xB3, 0x7E, 0xDD, 0xFF, 0xEC, 0};
    int challenge_rsp_len = sizeof(challenge_rsp);

    unsigned char E_expected_challenge_rsp[] = {0x77, 0x90, 0xAE, 0xE6, 0xE2, 0xDA, 0x41, 0xA3, 0x4A, 0x8B, 0x8E, 0x63, 0x4C, 0x0F, 0xD6, 0x80, 0xC1, 0xED, 0xAB, 0x08, 0x64, 0x38, 0x56, 0x1F, 0x69, 0xA5, 0x65, 0xF5, 0xDB, 0xEC, 0x49, 0xA8, 0};
    unsigned char E_expected_challenge_rsp_len = sizeof(E_expected_challenge_rsp);

    // Decrypt the expected challenge response that the manual gives
    unsigned char *expected_challenge_rsp;
    unsigned char expected_challenge_rsp_len;

    expected_challenge_rsp = aes_decrypt(E_expected_challenge_rsp, E_expected_challenge_rsp_len, &expected_challenge_rsp_len);
    printf("DChallenge: ");
    hexprint(expected_challenge_rsp, expected_challenge_rsp_len);

    // Re-encrypt it to see if I can do it.
    unsigned char *RE_expected_challenge_rsp;
    unsigned char RE_expected_challenge_rsp_len;

    RE_expected_challenge_rsp = aes_encrypt(expected_challenge_rsp, expected_challenge_rsp_len, &RE_expected_challenge_rsp_len);
    printf("REChallenge:");
    hexprint(RE_expected_challenge_rsp, RE_expected_challenge_rsp_len);

    // Now encrypt my challenge response
    unsigned char * E_challenge_rsp;
    int E_challenge_rsp_len;
    E_challenge_rsp = aes_encrypt(challenge_rsp, challenge_rsp_len, &E_challenge_rsp_len);
    printf("EChallenge: ");
    hexprint(E_challenge_rsp, E_challenge_rsp_len);

    aes_uninit();
}
#endif

int main(int argc, char **argv)
{
    demo_encrypt_decrypt();
    return 0;
}
