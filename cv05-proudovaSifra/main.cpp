#include <stdlib.h>
#include <openssl/evp.h>
#include <string.h>

#include <string>


int cipherIt(unsigned char  *openText, unsigned char * cipherText, unsigned char key[],unsigned char * initVector, const EVP_CIPHER * cipher, EVP_CIPHER_CTX *ctx )
{
    int otLength = (int) strlen((char *) openText);
    int stLength = 0;
    int tmpLength = 0;

    /* Sifrovani */
    // context init - set cipher, key, init-vector
    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, initVector) != 1) exit(3);
    // encryption of pt
    if (EVP_EncryptUpdate(ctx, cipherText, &tmpLength, openText, otLength) != 1) exit(4);
    stLength += tmpLength;
    // get the remaining ct
    if (EVP_EncryptFinal_ex(ctx, (cipherText) + stLength, &tmpLength) != 1) exit(5);
    stLength += tmpLength;

    return stLength;

}


void decypher(int otLength, unsigned char * cipherText, unsigned char key[],unsigned char * initVector, const EVP_CIPHER * cipher, EVP_CIPHER_CTX *ctx, unsigned char * desifText, int stLen )
{
    int tmpLength = 0;

    // nastaveni kontextu pro desifrovani
    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key, initVector) != 1) exit(6);

    // desifrovani cipherText
    if (EVP_DecryptUpdate(ctx, desifText, &tmpLength, cipherText, stLen) != 1) exit(7);
    otLength += tmpLength;

    // dokonceni (ziskani zbytku z kontextu)
    if (EVP_DecryptFinal_ex(ctx, (desifText )+ otLength, &tmpLength) != 1) exit(8);

}

int hex_to_int(char c)
{
    if (c >= 97)
        c = c - 32;
    int first = c / 16 - 3;
    int second = c % 16;
    int result = first * 10 + second;
    if (result > 9) result--;
    return result;
}

int hex_to_ascii(char c, char d){
    int high = hex_to_int(c) * 16;
    int low = hex_to_int(d);
    return high+low;
}

void convert(unsigned char st[], unsigned char stOut[])
{
    int length = strlen((char *) st);
    int i;
    char buf = 0;
    int j = 0;

    for(i = 0; i < length; i++){
        if(i % 2 != 0){
            stOut[j++] = hex_to_ascii(buf, st[i]);
        }else{
            buf = st[i];
        }
    }
}

/// TEST 2
// 5 bodu = RSA ; MUSIME ROZUMET TE ROVNICI
// NECO NA ENTROPII, VCETNE NAROZENINOVEHO PARADOXU
// JEDNOZNACNOST TAM NEBUDE
// MELO BY SE OBJEVIT NA EDUXU

int main() {
    OpenSSL_add_all_ciphers();

    const EVP_CIPHER *cipher;
    if (!(cipher = EVP_get_cipherbyname("RC4")))exit(1);


    /// context structure
    EVP_CIPHER_CTX *ctx;
    if (! (ctx = EVP_CIPHER_CTX_new()))exit(2);

    unsigned char openText[1024] = "Text pro rc4.";
    unsigned char key[EVP_MAX_KEY_LENGTH] = "Muj klic";
    unsigned char initVector[EVP_MAX_IV_LENGTH] = "asdfsadf";

    unsigned char cipherText[1024];
    int stLen = cipherIt(openText,cipherText,key,initVector,cipher,ctx);


   // printf("OT:\t%s", openText);
   // printf("\t(sifruji do %d znaku)\n", stLen);

    ///print ciphered
   // printf("ST:\t");
   // for (int i = 0; i < sizeof((char *)cipherText); i ++)
   //     printf("%2x", cipherText[i]);

    unsigned char decypheredText[1024];

    decypher(13,cipherText,key,initVector,cipher,ctx, decypheredText,  stLen);

    ///prind deciphered
  //  printf("\nDT:\t");
  //  for (int i = 0; i < sizeof((char *) decypheredText); i ++)
  //      printf("%2x", decypheredText[i]);
  //  printf("\t'%s'\n", decypheredText);

    EVP_CIPHER_CTX_free(ctx);

    unsigned char st1[] = "06fb7405eba8d9e94fb1f28f0dd21fdec55fd54750ee84d95ecccf2b1b48";
    unsigned char st2[] = "33f6630eaea4dba152baf38d019c04cbc759c94544fb9a815dc68d7b5f1a";
    unsigned char ot1[1024] = "abcdefghijklmnopqrstuvwxyz0123";

    unsigned char ot1Int[1024];
    unsigned char st1Int[1024];
    unsigned char st2Int[1024];

    convert(st1,st1Int);
    convert(st2,st2Int);

    unsigned char result[1024];


    // xor
    for (int j = 0; j < 30; ++j)
        result[j] = st1Int[j] ^ st2Int[j];

    // xor
    for (int j = 0; j < 30; ++j)
            result[j] = result[j] ^ ot1[j];

    printf("\nDT:\t%s", result);

}