#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h> 
#include "openssl/err.h"

// Create the SSL socket and intialize the socket address structure
int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;


    sd = socket(PF_INET, SOCK_STREAM, 0);   //create a socket
    bzero(&addr, sizeof(addr)); //padding
    
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
/*
    Check if its a root user.
 */
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;

	/* load & register all cryptos, etc. */
	OpenSSL_add_all_algorithms();

    /* load all error messages */
    SSL_load_error_strings();
    
	/* create new server-method instance */
    method = TLSv1_2_server_method();

	/* create new context from method */
    ctx = SSL_CTX_new(method);

    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }

}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

	/* Get certificates (if available) */
    cert = SSL_get_peer_certificate(ssl);

    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        /* */
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        /* */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse="<\\Body>\
                               <Name>sousi.com</Name>\
                 <year>1.5</year>\
                 <BlogType>Embedede and c\\c++<\\BlogType>\
                 <Author>John Johny<Author>\
                 <\\Body>";
    const char *cpValidMessage = "<Body>\
                               <UserName>sousi<UserName>\
                 <Password>123<Password>\
                 <\\Body>";
	/* do SSL-protocol accept */
    if (SSL_accept(ssl) == -1) 
        ERR_print_errors_fp(stderr); /*else print "Invalid Message" */
    else
    {
        ShowCerts(ssl);
        bytes = SSL_read(ssl, buf, sizeof(buf)); 
        buf[bytes] = '\0';

        printf("Client msg: \"%s\"\n", buf);

        if (bytes > 0)
        {
            if (strcmp(cpValidMessage, buf) == 0)
            {
                SSL_write(ssl, ServerResponse, strlen(ServerResponse));
            }
            else
            {
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message"));
            }
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }

        sd = SSL_get_fd(ssl);
        SSL_free(ssl);
        close(sd);
    }
  
  
	/* get socket connection */
	/* release SSL state */
  /* close connection */
}
int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;

//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }

    // Initialize the SSL library
    SSL_library_init();

    portnum = Argc[1];
    /* initialize SSL */
    ctx = InitServerCTX();
    /* load certs */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");

    /* create server socket */
    server = OpenListener(atoi(portnum));

    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

			/* accept connection as usual */
        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

		/* get new SSL state with context */
		ssl = SSL_new(ctx);
        
        /* set connection socket to SSL state */
        SSL_set_fd(ssl, client);

		/* service connection */
        Servlet(ssl);
    }
		/* close server socket */
        close(server);
		/* release context */
        SSL_CTX_free(ctx);
}
