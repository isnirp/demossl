#include "comm_asymmetric_channel.h"

/* handle ssl errors*/
void handle_error(const char *msg)
{
    perror(msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

/* initialise ssl library*/
void init_ssl()
{
    SSL_load_error_strings();
    SSL_library_init();
}

/*
* SSL_CTX; a structure that holds SSL information
* creates a new connection object for each ssl connection
* the connection objects are used to do ssl handshakes, read and write
*/
int init_CTX(entity obj)
{
    /* SSL method; SSLv2, SSLv3, TLSv1 */
    const SSL_METHOD *method = SSLv23_method(); /* SSLv23_method for both client and server*/

    obj.ctx = SSL_CTX_new(method);
    if (obj.ctx == NULL)
    {
        handle_error("SSL_CTX init \n");
    }

    return 0;
}

/*
*set up a certificate for the object; this is loaded into the ctx structure
*the certificate also contains the public key of the object
*/
int load_cert(entity obj)
{
    /* local certificate */
    char cert[1024];
    sprintf(cert, "./%s-cert.pem", (char *)obj.mode);

    /*
    *load a certificate into an SSL_CTX structure or ssl object 
    * formatting types; SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1
    * SSL_FILETYPE_PEM serializes data to a Base64-encoded encoded representation of the underlying ASN.1 data structure
    * -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
    */
    if (SSL_CTX_use_certificate_file(obj.ctx, cert, SSL_FILETYPE_PEM) != 1)
    {
        handle_error("Loading cert failed \n");
    }

    printf("certificate successfully loaded \n");
    printf("cert: %s \n", (char *)cert);
    return 0;
}

/* set a private key that corresponds to objects certificate */
int load_private_key(entity *obj, char name)
{
    /* local key */
    char key[1024];
    sprintf(key, "./%s-key.pem", name);
    /* load private key into an SSL_CTX structure or ssl object */
    if (SSL_CTX_use_PrivateKey_file(obj->ctx, key, SSL_FILETYPE_PEM) != 1)
    {
        handle_error("Loading key failed \n");
    }

    /* verify private key matches cert */
    if (!SSL_CTX_check_private_key(obj->ctx))
    {
        handle_error("Key verification failed \n");
    }

    printf("private key successfully loaded \n");
    return 0;
}

/*
* using a server (1) and client (0) concept
*
*/
int open_connection(entity *obj, enum ssl_mode)
{
    /* get new SSL state with context */
    obj->ssl = SSL_new(obj->ctx);
    obj->rbio = BIO_new(BIO_s_mem());
    obj->wbio = BIO_new(BIO_s_mem());

    /* connect the SSL object with a BIO */
    SSL_set_bio(obj->ssl, obj->rbio, obj->wbio);

    if (ssl_mode == MODE_SERVER)
    {
        SSL_set_connect_state(obj->ssl);
        sprintf(obj->mode, "%s", "MODE_SERVER");
    }
    else
    {
        SSL_set_accept_state(obj->ssl);
        sprintf(obj->mode, "%s", "MODE_CLIENT");
    }

    /* establish ssl connection; if successful(1->success, 0->fail) perform handshake */
    int r = SSL_connect(obj->ssl);

    printf("%s connection ready \n", obj->mode);

    return r;
}

/* verify server cert */
int verify_cert(entity *obj, char cert_name)
{
    char cert_path[1024];
    sprintf(cert_path, "./%s-cert.pem", cert_name);

    if (!SSL_CTX_load_verify_locations(obj->ctx, cert_path, NULL))
    {
        handle_error("SSL_CTX_load_verify_locations \n");
    }

    long verify_flag = SSL_get_verify_result(ssl);
    if (verify_flag != X509_V_OK)
    {
        // handle error
        fprintf(stderr, "Certificate verification error (%i) but continuing...\n", (int)verify_flag);
    }

    return 0;
}

int awrite_to_channel(entity *obj, char buf)
{
    printf("writing to %s \n", obj->mode);
    /* SSL_write accepts an unencrypted buf and sends it to the ssl obj for encryption.
    * the results is stored in the output buf wbio
    * 
    * **/
    int w = SSL_write(obj->ssl, buf, sizeof(buf));
    if (w > 0)
    {
        /* the encrypted data is written into the output buf (wbio) of the obj*/
        BIO_write(obj->wbio, buf, sizeof(buf));
        printf("%s wrote %s into BIO memory\n", obj->mode, buf);
    }
    /* write encrypted buf into memory(rbio)*/
    // BIO_write(bio, "hello, World!\n", 14);
    //BIO_write(obj_to->rbio, obj_to->buf, sizeof(obj_to->buf));
    return 0;
}

int aread_from_channel(entity *obj_from, entity *obj_to, char *buf)
{
    printf("reading from %s \n", obj_from->mode);
    /* assume obj_from (T1), obj_to (T2)*/
    int r_t1 = 0;
    int r_t2 = 0;
    int w_t2 = 0;
    /* check if T1 has anything in its output bio(wbio) for T2*/
    int pending = BIO_ctrl_pending(obj_from->wbio);
    if (pending > 0)
    {
        /*read encrypted data from ouput bio(wbio) of T1 into temporary buf for reading by T2*/
        r_t1 = BIO_read(obj_from->wbio, buf, sizeof(buf));
    }

    if (r_t1 > 0)
    {
        /*write encrypted data buf into the input bio(rbio) of T2*/
        w_t2 = BIO_write(obj_to->rbio, buf, r_t1);
    }

    if (w_t2 > 0)
    {
        /*read the decrypted message into buf*/
        read = SSL_read(obj_to->ssl, buf, sizeof(buf));
        printf("%s read from BIO memory into %s\n", obj_to->mode, buf);
    }

    return 0;
}
