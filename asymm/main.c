#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <stdbool.h>

#include "comm_asymmetric_channel.h"
#include "bob.h"
#include "alice.h"

//BIO *rbio;
//BIO *wbio;
void init_OpenSSL()
{
    if (!SSL_library_init())
    {
        printf("init failed");
        exit(1);
    }
    SSL_load_error_strings();
}

int main(int argc, char *argv[])
{
    mainFunc__Alice();
    mainFunc__Bob();
    SSL_do_handshake(bob.ssl);
    //alice writes
    //awrite_to_channel(&alice, &bob, (char *)"Hello WOrld");
    awrite_to_channel(&bob, &alice, (char *)"Hello WOrld");
    //bob reads
    //aread_from_channel(&bob);
    aread_from_channel(&alice);
    /* awrite_to_channel(&bob, &alice, (char *)"Hello WOrld");
    aread_from_channel(&alice);
    awrite_to_channel(&alice, &bob, (char *)"Hi WOrld");
    aread_from_channel(&bob); */

    return 0;
}

//gcc main.c -o main -lcrypto -lssl -g