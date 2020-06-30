#ifndef COMM_ASYMMETRIC_CHANNEL_H
#define COMM_ASYMMETRIC_CHANNEL_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <unistd.h>
#include <string.h>

typedef struct
{
    SSL_CTX *ctx;  /*SSL_CTX;a structure that holds SSL information*/
    SSL *ssl;      /* SSL object handles the connection */
    BIO *rbio;     /* SSL reads from, we write to. */
    BIO *wbio;     /* SSL writes to, we read from. */
    char mode[32]; /* server or client mode*/
    char name[32]; /* obj name or mode*/
} entity;

extern entity alice;
extern entity bob;

enum ssl_mode
{
    MODE_SERVER,
    MODE_CLIENT
}; /* modes for connection */

void handle_error(const char *msg);
void init_ssl();
int init_CTX(entity *obj);
int load_cert(entity *obj);
int load_private_key(entity *obj);
int open_connection(entity *obj, enum ssl_mode smode);
int verify_cert(entity *obj, char *cert_name);
int awrite_to_channel(entity *obj, entity *obj_to, char *buf);
int aread_from_channel(entity *obj);

#endif