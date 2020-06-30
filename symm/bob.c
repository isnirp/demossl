#include "bob.h"

entitysym bob;
unsigned char decryptedtext[128];
unsigned char texttodecrypt[128];

/* Bob receives cipher text and decrypts*/
void mainFunc__Bob()
{
    bob.key = keys;
    bob.bio = wbio;
    sprintf(bob.mode, "%s", "Bob");

    /* Message to be decrypted */
    read_channel(bob.mode, bob.bio, texttodecrypt, ciphertext_len);

    do_decrypt(texttodecrypt, ciphertext_len, decryptedtext, bob);
    printf("Decrypted text is %s\n", decryptedtext);
}