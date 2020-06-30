#ifndef COMM_SYMMETRIC_CHANNEL_H
#define COMM_SYMMETRIC_CHANNEL_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include <unistd.h>
#include <string.h>

typedef struct
{
    BIO *bio;
    unsigned char *key;
    unsigned char *iv;
    char mode[32];
} entitysym;

/* Key to use for encrpytion and decryption */
//extern unsigned char keys[AES_256_KEY_SIZE];
/* Initialization Vector */
//extern unsigned char ivs[AES_BLOCK_SIZE];

extern unsigned char keys[32];
extern unsigned char ivs[16];

/* shared memory as the channel */
extern BIO *rbio;
extern BIO *wbio;

extern int ciphertext_len;

/* Buffer for the cipher text */
//extern unsigned char ciphertext[128];
/* Buffer for the decrypted text */
//extern unsigned char decryptedtext[128];

//examples
//extern int world;
//extern char *world;

void handle_error(const char *msg);
void init_ssl();
int open_channel(BIO *wbio, BIO *rbio);
int generate_key_iv(unsigned char *key, unsigned char *iv);
int do_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, entitysym obj);
int do_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, entitysym obj);
int send_channel(char *sender, BIO *bio, unsigned char *ciphertext, int ciphertext_len);
int read_channel(char *receiver, BIO *bio, unsigned char *decryptedtext, int decryptedtext_len);
//int send_channel(BIO *rbio, unsigned char *ciphertext, int ciphertext_len);
//int read_channel(BIO *wbio, unsigned char *decryptedtext, int decryptedtext_len);

#endif