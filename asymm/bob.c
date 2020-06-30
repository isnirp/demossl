#include "bob.h"

entity bob;
enum ssl_mode sm = MODE_CLIENT;

/* Bob receives cipher text and decrypts*/
void mainFunc__Bob()
{
    sprintf(bob.name, "%s", "Bob");
    sprintf(bob.mode, "%s", "MODE_CLIENT");
    init_ssl();
    init_CTX(&bob);
    open_connection(&bob, sm);
    verify_cert(&bob, (char *)"Alice");
    //SSL_do_handshake(bob.ssl);
}