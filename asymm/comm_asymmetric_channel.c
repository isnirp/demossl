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
int init_CTX(entity *obj)
{
    /* SSL method; SSLv2, SSLv3, TLSv1 */
    //const SSL_METHOD *method = SSLv23_method(); /* SSLv23_method for both client and server*/
    const SSL_METHOD *method;
    if (obj->mode == "MODE_SERVER")
    {
        method = SSLv3_server_method();
    }
    else
    {
        method = SSLv3_client_method();
    }
    obj->ctx = SSL_CTX_new(method);
    if (obj->ctx == NULL)
    {
        handle_error("SSL_CTX init \n");
    }

    return 0;
}

/*
*set up a certificate for the object; this is loaded into the ctx structure
*the certificate also contains the public key of the object
*/
int load_cert(entity *obj)
{
    /* local certificate */
    char cert[1024];
    sprintf(cert, "./%s-cert.pem", (char *)obj->name);

    /*
    *load a certificate into an SSL_CTX structure or ssl object 
    * formatting types; SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1
    * SSL_FILETYPE_PEM serializes data to a Base64-encoded encoded representation of the underlying ASN.1 data structure
    * -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
    */
    if (SSL_CTX_use_certificate_file(obj->ctx, cert, SSL_FILETYPE_PEM) != 1)
    {
        handle_error("Loading cert failed \n");
    }

    printf("certificate successfully loaded \n");
    printf("cert: %s \n", (char *)cert);
    return 0;
}

/* set a private key that corresponds to objects certificate */
int load_private_key(entity *obj)
{
    /* local key */
    char key[1024];
    sprintf(key, "./%s-key.pem", obj->name);
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

int open_connection(entity *obj, enum ssl_mode smode)
{
    /* get new SSL state with context */
    obj->ssl = SSL_new(obj->ctx);
    obj->rbio = BIO_new(BIO_s_mem());
    obj->wbio = BIO_new(BIO_s_mem());

    /* connect the SSL object with a BIO */
    SSL_set_bio(obj->ssl, obj->rbio, obj->wbio);

    if (smode == MODE_SERVER)
    {
        SSL_set_accept_state(obj->ssl);
        //SSL_set_connect_state(obj->ssl);
        sprintf(obj->mode, "%s", "MODE_SERVER");
        printf("%s connection in MODE_SERVER mode waiting hanshake\n", obj->name);
    }
    else
    {
        //SSL_CTX_set_verify(obj->ctx, SSL_VERIFY_NONE, NULL);
        SSL_set_connect_state(obj->ssl); /* client */
        //SSL_set_accept_state(obj->ssl); /*server*/
        sprintf(obj->mode, "%s", "MODE_CLIENT");
        printf("%s connection in MODE_CLIENT mode expecting handshake\n", obj->name);
    }

    /* establish ssl connection; if successful(1->success, 0->fail) perform handshake */
    int r = SSL_connect(obj->ssl);

    printf("%s connection ready \n", obj->mode);

    return r;
}

/****************************/
/* verify server cert */
int verify_cert(entity *obj, char *cert_name)
{
    char cert_path[1024];
    sprintf(cert_path, "./%s-cert.pem", cert_name);
    printf("%s\n", cert_path);

    if (!SSL_CTX_load_verify_locations(obj->ctx, cert_path, NULL))
    {
        handle_error("SSL_CTX_load_verify_locations \n");
    }

    long verify_flag = SSL_get_verify_result(obj->ssl);
    if (verify_flag != X509_V_OK)
    {
        // handle error
        fprintf(stderr, "Certificate verification error (%i) but continuing...\n", (int)verify_flag);
    }
    else
    {
        printf("cert verified\n");
    }

    return 0;
}

int awrite_to_channel(entity *obj, entity *obj_to, char *buf)
{
    printf("writing to BIO %s \n", obj->name);
    /* SSL_write accepts an unencrypted buf and sends it to the ssl obj for encryption.
    * the results is stored in the output buf wbio
    * 
    * **/
    char outbuf[1024];
    int read = 0;
    int w = SSL_write(obj->ssl, buf, sizeof(buf));
    int pending = BIO_ctrl_pending(obj->wbio);

    if (pending > 0)
    {
        read = BIO_read(obj->wbio, outbuf, sizeof(outbuf));
        printf("pending message\n");
        printf("message: %s\n", (char *)outbuf);
    }

    if (read > 0)
    {
        BIO_write(obj_to->rbio, outbuf, read);
        printf("%s written to BIO of %s \n", obj->name, obj_to->name);
    }
    /* if (w > 0)
    { */
    /* the encrypted data is written into the output buf (wbio) of the obj*/
    /*     BIO_write(obj->wbio, buf, sizeof(buf));
        printf("%s wrote %s into BIO memory\n", obj->name, buf);
    }
    else
    {
        printf("writing to channel failed\n");
    } */
    /* write encrypted buf into memory(rbio)*/
    // BIO_write(bio, "hello, World!\n", 14);
    //BIO_write(obj_to->rbio, obj_to->buf, sizeof(obj_to->buf));
    return 0;
}

int aread_from_channel(entity *obj)
{
    printf("reading from BIO of %s...\n", obj->mode);

    char outbuf[1024];
    int r = 0;

    /* check if T1 has any pending message from T2*/
    int pending = BIO_ctrl_pending(obj->rbio);
    if (pending > 0)
    {
        /*read encrypted data from ouput bio */
        r = BIO_read(obj->rbio, outbuf, sizeof(outbuf));
        printf("pending message for %s...\n", obj->name);
    }

    if (r > 0)
    {
        printf("decrypting message for %s...\n", obj->name);
        /* decrypt message */
        /* r = SSL_read(obj->ssl, outbuf, sizeof(outbuf));
        if (r > 0)
            printf("%s read: %s\n", obj->name, outbuf); */
        if (!SSL_is_init_finished(obj->ssl))
        {
            SSL_do_handshake(obj->ssl);
            printf("handshaking\n");
        }
        else
        {
            sprintf(outbuf, "%s", "testing");
            SSL_read(obj->ssl, outbuf, sizeof(outbuf));
            printf("%s read: %s\n", obj->name, outbuf);
        }
    }

    return 0;
}
