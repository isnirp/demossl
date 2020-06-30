#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#include "comm_symmetric_channel.h"
#include "bob.h"
#include "alice.h"

//char *world = "fr";

unsigned char keys[32], ivs[16];

//BIO *rbio;
BIO *wbio;

int main(int argc, char *argv[])
{
    init_ssl();

    generate_key_iv(keys, ivs);

    wbio = BIO_new(BIO_s_mem());
    //rbio = BIO_new(BIO_s_mem());

    open_channel(wbio, wbio);

    mainFunc__Alice();

    mainFunc__Bob();

    return 0;
}

//gcc main.c -o main -lcrypto -lssl -g