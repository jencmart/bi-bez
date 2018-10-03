#include <cstdio>
#include <cstring>
#include <openssl/evp.h>


static char * rand_string(char *str, size_t size) {
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++)
            str[n] =  (char)(rand()%'z'+'a');
        str[size] = '\0';
    }
    return str;
}

char* rand_string_alloc(size_t size)
{
    char *s = (char *) malloc(size + 1);
    if (s) {
        rand_string(s, size);
    }
    return s;
}

void hashIt(char * text, char t [], EVP_MD_CTX * ctx)
{
    /// create type of hash function
    const EVP_MD * type;
    if(! (type = EVP_get_digestbyname(t)) )
        exit(1);

    int res;
    // char pole pro hash - 64 bytu (max pro sha 512)
    unsigned char hash[EVP_MAX_MD_SIZE];

    /* Hash the text */
    res = EVP_DigestInit_ex(ctx, type, nullptr); // context setup for our hash type
    if(res != 1) exit(3);
    res = EVP_DigestUpdate(ctx, text, strlen(text)); // feed the message in
    if(res != 1) exit(4);

    int length;
    res = EVP_DigestFinal_ex(ctx, hash, (unsigned int *) &length); // get the hash
    if(res != 1) exit(5);

    if((hash[0] ==  170 && hash[1] == 187) )
    {
        for(int i = 0; i < length; i++)
            printf("%02X", hash[i]);
        printf("\t%s\n", text);
    }
}

int main(int argc, char *argv[])
{
    /// Inicializace OpenSSL hash funkci
    OpenSSL_add_all_digests();

    /// create context for hashing
    EVP_MD_CTX *ctx;
    if(! (ctx = EVP_MD_CTX_create()))
        exit(2);

    char typ[] = "sha1";

    char text[5];
    for(char i = 'a' ; i <= 'z' ; i++)
            for (char j = 'a'; j <= 'z'; j++)
                for (char k = 'a'; k <= 'z'; k++)
                    for (char l = 'a'; l <= 'z'; l++) {
                        text[0] = i;
                        text[1] = j;
                        text[2] = k;
                        text[3] = l;
                        text[4] = '\0';
                        hashIt(text,typ, ctx);
                    }

    /// destroy the context
    EVP_MD_CTX_destroy(ctx);

}