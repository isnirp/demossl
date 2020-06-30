//#include "comm_symmetric_channel.h"
#include "alice.h"

/* unsigned char ciphertext[128];
int ciphertext_len; */

entity alice;
entity bob;
enum ssl_mode smode = MODE_SERVER;

void mainFunc__Alice()
{
    sprintf(alice.name, "%s", "Alice");
    sprintf(alice.mode, "%s", "MODE_SERVER");
    init_ssl();
    init_CTX(&alice);
    //openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
    load_cert(&alice);
    load_private_key(&alice);
    open_connection(&alice, smode);
    //awrite_to_channel(&alice, (char *)"Hello WOrld");
}