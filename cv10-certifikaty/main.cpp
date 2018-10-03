#include <arpa/inet.h>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <openssl/ssl.h>
#include <strings.h>
#include <unistd.h>

using namespace std;

int main(int argc, char *argv[]) {
    string ipv4 = "147.32.232.248";
    uint16_t port = 443;

    /// CONNECT
    printf("\nConnecting %s:%u...", ipv4.c_str(), port);
    int sockFd;
    struct sockaddr_in servaddr{};
    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ipv4.c_str());
    servaddr.sin_port = htons(port);
    if (0 != connect(sockFd, (struct sockaddr *) &servaddr, sizeof(servaddr))) exit(1);
    printf("OK\n");

    /// SET UP HTTPS
    printf("Setting up SSL...");
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());


    // todo LAB 6. - SSL_CTX_load_verify_locations
    if(  SSL_CTX_set_default_verify_paths(ctx) != 1) exit(11);
    // todo

    if (!ctx) exit(2);
    if (!SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1))exit(2);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) exit(3);
    if (!SSL_set_fd(ssl, sockFd)) exit(4);

    // todo LAB  6. - po zakazu se dohodli na ECDHE-RSA-AES128-GCM-SHA256 (priorita 12)
    SSL_set_cipher_list(ssl,"ALL:!ECDHE-RSA-AES256-GCM-SHA384");
    // todo

    if (SSL_connect(ssl) <= 0) exit(5);

    // todo LAB 6. - verify verification result
    if( SSL_get_verify_result(ssl) == X509_V_OK)
        printf("The verification succeeded...");
    else
    {
        printf("Verification not succeeded: %ld", SSL_get_verify_result(ssl));
        exit(6);
    }


    /// DOWNLOAD CERTIFICATE
    printf("Downloading certificate...");
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) exit(6);
    printf("OK\n");

    /// WRITE CERTIFICATE
    printf("Writing certificate...");
    FILE *file_PEM = fopen("../cert.pem", "w");
    if (!PEM_write_X509(file_PEM, cert)) exit(7);
    fclose(file_PEM);
    printf("OK\n\n");


    printf("OK\n\n");

    /// WEB REQUEST
    printf("HTTP request...");
    string req = "GET / HTTP/1.1\r\nHost: fit.cvut.cz/student/rozvrh\r\n\r\n";
    if (SSL_write(ssl, req.c_str(), static_cast<int>(req.length())) <= 0)exit(8);
    printf("OK\n");

    /// WRITE RESPONSE TO FILEpi
    printf("Writing HTTP response...");
    fflush(stdout);
    ofstream responseFile("../response", ios::out);
    if (!responseFile) exit(9);
    char buffer[1024];
    for (int read_size = 0; (read_size = SSL_read(ssl, buffer, 1024)) > 0;)
        if (!responseFile.write((char *) buffer, read_size))
            exit(11);
    printf("OK\n\n");



    // todo LAB  6. CURRENT CIPHER + CIPHER LIST
    printf("Current cipher...%s\n\n",  SSL_CIPHER_get_name( SSL_get_current_cipher(ssl) ) );
    printf("Cipher list:\n");
    for (int i = 0; SSL_get_cipher_list(ssl, i); ++i)
        printf("%d. %s\n", i, SSL_get_cipher_list(ssl, i));
    // todo

    /// FREE AND CLOSE ALL
    responseFile.close();
    SSL_shutdown(ssl);
    close(sockFd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    printf("\n...all done! exiting now\n");
}
