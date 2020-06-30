#include "comm_symmetric_channel.h"

void handle_error(const char *msg)
{
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_ssl()
{
    printf("Initializing ssl...\n");
    SSL_load_error_strings();
    SSL_library_init();
}

int open_channel(BIO *wbio, BIO *rbio)
{
    printf("openning channel...\n");

    const SSL_METHOD *method = SSLv23_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL *ssl = SSL_new(ctx);

    SSL_set_bio(ssl, rbio, wbio);
}

//int send_channel(BIO *rbio, unsigned char *ciphertext, int ciphertext_len)
int send_channel(char *sender, BIO *bio, unsigned char *ciphertext, int ciphertext_len)
{
    //write ciphertext into the input bio of target
    int x = BIO_write(bio, ciphertext, ciphertext_len);
    if (x > 0)
    {
        printf("%s is sending to channel...\n", sender);
    }

    return x;
}

int read_channel(char *receiver, BIO *bio, unsigned char *decryptedtext, int decryptedtext_len)
//int read_channel(entitysym obj, unsigned char *decryptedtext, int decryptedtext_len)
{
    int x = BIO_read(bio, decryptedtext, decryptedtext_len);
    if (x > 0)
    {
        printf("%s is receiving from channel...\n", receiver);
    }

    return x;
}

/*
*openssl enc -aes-256-cbc -k password -nosalt -p < /dev/null
**/
int generate_key_iv(unsigned char *key, unsigned char *iv)
{
    printf("---generating key---\n");
    const EVP_CIPHER *cipher;
    const EVP_MD *dgst = NULL;

    const char *key_data = "motdepass";

    //cipher = EVP_get_cipherbyname("aes-256-cbc");
    cipher = EVP_aes_256_cbc();
    if (!cipher)
    {
        //handle error
        printf("Error Cipher\n");
    }

    //dgst = EVP_get_digestbyname("md5");
    dgst = EVP_md5();
    if (!dgst)
    {
        //handle error
        printf("Error Digest\n");
    }

    //EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
    /* generating the key and iv */
    if (!EVP_BytesToKey(cipher, dgst, NULL, (unsigned char *)key_data, strlen(key_data), 1, key, iv))
    {
        //handle error
        printf("Error bytes to key\n");
    }

    printf("key generated:");
    for (int i = 0; i < cipher->key_len; ++i)
    {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("IV generated:");
    for (int i = 0; i < cipher->iv_len; ++i)
    {
        printf("%02x", iv[i]);
    }
    printf("\n");

    return 0;
}

/*
*
*do encryption
*We are using EVP interface for encryption and decryption of messages
*EVP provides a set of user-level functions that can be used to perform various cryptographic operations
*plaintext; data to be encrypted
*ciphertext; buffer for encrypted data
*/
int do_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext, entitysym obj)
{
    printf("%s is encrypting data...\n", obj.mode);
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* ctx setup: initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        //handle error
    }

    /* Initialise the encryption operation: using cipher 256 bit AES */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, obj.key, obj.iv))
    {
        //handle error
        printf("Error evp_encrypt_init\n");
    }

    /*
     * Provide the message (plaintext) to be encrypted, and obtain the encrypted output (ciphertext).
     */
    // EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    //                             int *outl, const unsigned char *in, int inl)
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        //handle error
        printf("Error evp_encrypt_update\n");
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    //EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,int *outl)
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        //handle error
        printf("Error encrypt_final\n");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*
*
*do decryption
*We are using EVP interface for encryption and decryption of messages
*EVP provides a set of user-level functions that can be used to perform various cryptographic operations
*/
int do_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext, entitysym obj)
{
    printf("Decrypting cipher for %s \n", obj.mode);
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        //handle error
    }

    /* Initialise the decryption operation: initialise the context using cipher 256 bit AES  */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, obj.key, obj.iv))
    {
        //handle error
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    // EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
    //                            int *outl, const unsigned char *in, int inl)
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        //handle error
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        //handle error
    }

    plaintext_len += len;

    /* Add the null terminator */
    plaintext[plaintext_len] = 0;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}