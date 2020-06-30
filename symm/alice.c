//#include "comm_symmetric_channel.h"
#include "alice.h"

entitysym alice;
unsigned char ciphertext[128];
int ciphertext_len;

//void *mainFunc__Alice(void *arg)
void mainFunc__Alice()
{
    alice.key = keys;
    alice.bio = wbio;
    sprintf(alice.mode, "%s", "Alice");

    /* Message to be encrypted */
    unsigned char *plaintext = (unsigned char *)"Hello World";

    ciphertext_len = do_encrypt(plaintext, strlen((char *)plaintext), ciphertext, alice);

    printf("Ciphertext is: %s\n", ciphertext);

    send_channel(alice.mode, alice.bio, ciphertext, ciphertext_len);

    //examples
    //printf("keys %s \n", (unsigned char *)keys);
    //printf("hello %s \n", (char *)world);
    //printf("hello %s \n", world);
    //printf("Alice keys: %s \n", (char *)alice.key);
}