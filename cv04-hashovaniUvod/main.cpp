#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>



int main(void) {
    EVP_CIPHER_CTX * context = EVP_CIPHER_CTX_new();
    OpenSSL_add_all_ciphers();
    const EVP_CIPHER * sifra = EVP_get_cipherbyname("RC4");

    unsigned char buffer_out[1024];
    int cbBuffer_out = 0;


    unsigned char buffer_in[] = "Hello sweet world";
    unsigned char sifra_klic[] = "123456789";
    unsigned char sifra_iv[] = "098765432";

    int cbWritten = 0;

    /* Sifrovani */
    EVP_EncryptInit(context, sifra, sifra_klic, sifra_iv);  // nastaveni kontextu pro sifrovani
    EVP_EncryptUpdate(context, buffer_out, &cbBuffer_out, buffer_in, static_cast<int>(strlen((char*)buffer_in)));  // sifrovani ot
    EVP_EncryptFinal(context, buffer_out, &cbWritten);  // dokonceni (ziskani zbytku z kontextu)


    for (int i = 0; i < cbBuffer_out; ++i)
        printf("%02x", buffer_out[i]);

    printf("\n");
    unsigned char buffer_decrypted[1024];
    int cbBuffer_decrypted = 0;
    /* Desifrovani */
    EVP_DecryptInit(context, sifra, sifra_klic, sifra_iv);  // nastaveni kontextu pro desifrovani
    EVP_DecryptUpdate(context, buffer_decrypted, &cbBuffer_decrypted,  buffer_out, cbBuffer_out);  // desifrovani st

    EVP_DecryptFinal(context, buffer_decrypted, &cbWritten);  // dokonceni (ziskani zbytku z kontextu)


    for (int i = 0; i < cbBuffer_decrypted; ++i)
        printf("%02x", buffer_decrypted[i]);

    exit(0);
}

int hashovani(int argc, char *argv[]){

    int i;
    char text[] = "Text pro hash.";
    char hashFunction[] = "sha1";  // zvolena hashovaci funkce ("sha1", "md5" ...)

    EVP_MD_CTX  * ctx   = EVP_MD_CTX_new();  // struktura kontextu
    const EVP_MD *type; // typ pouzite hashovaci funkce
    unsigned char hash[EVP_MAX_MD_SIZE]; // char pole pro hash - 64 bytu (max pro sha 512)
    int length;  // vysledna delka hashe

    /* Inicializace OpenSSL hash funkci */
    OpenSSL_add_all_digests();
    /* Zjisteni, jaka hashovaci funkce ma byt pouzita */
    type = EVP_get_digestbyname(hashFunction);

    /* Pokud predchozi prirazeni vratilo -1, tak nebyla zadana spravne hashovaci funkce */
    if(!type) {
        printf("Hash %s neexistuje.\n", hashFunction);
        exit(1);
    }

    /* Provedeni hashovani */
    EVP_DigestInit(ctx, type);  // nastaveni kontextu
    EVP_DigestUpdate(ctx, text, strlen(text));  // zahashuje text a ulozi do kontextu
    EVP_DigestFinal(ctx, hash, (unsigned int *) &length);  // ziskani hashe z kontextu

    /* Vypsani vysledneho hashe */
    printf("Hash textu \"%s\" je: ", text);
    for(i = 0; i < length; i++){
        printf("%02x", hash[i]);
    }
    printf("\n");

    exit(0);
}