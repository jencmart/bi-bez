//jencmart
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <cstring>

#define BUFFER_SIZE 512

using namespace std;


/// OPEN FILE HELPER
FILE * openFile(const string &filename, const string &type) {
    FILE *file;
    if (!(file = fopen(filename.c_str(), type.c_str()))) {
        printf("Error opening %s\n", filename.c_str());
        exit (1);
    }
    return file;
}

/// *************** ENCRYPT PROGRAM *********************
void encrypt(const string & publicKeyPath, const string & inputFilePath) {
    string outputFilePath = "../encryptedFile";

    /// READ KEY
    FILE *  f = openFile(publicKeyPath, "r");
    EVP_PKEY *pubKey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);

    /// CIPHER INITIALIZATION
    OpenSSL_add_all_ciphers();
    auto *encryptKey = (unsigned char *)malloc(static_cast<size_t>(EVP_PKEY_size(pubKey)));
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) exit(2);
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int encryptKeyLen;
    if (!(EVP_SealInit(ctx, cipher, &encryptKey, &encryptKeyLen, iv, &pubKey, 1)))
        exit(3);


    /// INPUT OUTPUT FILES
    FILE *input = openFile(inputFilePath, "r");
    FILE *output = openFile(outputFilePath, "w");


    /// WRITE HEAD
    string cipherName = "aes-256-cbc";
    fwrite(cipherName.c_str(), sizeof(unsigned char), strlen(cipherName.c_str()), output);
    fprintf(output, "%d", encryptKeyLen);
    fwrite(encryptKey, sizeof(unsigned char), static_cast<size_t>(encryptKeyLen), output);
    fwrite(iv, sizeof(unsigned char), EVP_MAX_IV_LENGTH, output);
    /// print head...
    printf ("key: ");
    for (int i = 0; i < encryptKeyLen; i++)
        printf("%02x", encryptKey[i]);
    printf("\nIV:");
    for (unsigned char i : iv)
        printf("%02x", i);

    /// CIPHER
    int res;

    /* cipher main part */
    unsigned char buffer[BUFFER_SIZE];
    unsigned char bufferOut[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int length = 0;
    int encrytDataLen = 0;
    while ((res = static_cast<int>(fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input)))) {
        if (1 != EVP_SealUpdate(ctx, bufferOut, &encrytDataLen, buffer, res)) exit(4);
        fwrite(bufferOut, sizeof(unsigned char), static_cast<size_t>(encrytDataLen), output);
        length += encrytDataLen;
    }

    /* cipher last block */
    if (!EVP_SealFinal(ctx, bufferOut, &encrytDataLen)) exit(5);
    fwrite(bufferOut, sizeof(unsigned char), static_cast<size_t>(encrytDataLen), output);
    length += encrytDataLen;
    free(encryptKey);


    printf("\ntotal length: %d", length);
    fclose(input);
    fclose(output);
}



/// ************* DECRYPT PROGRAM ****************
void decrypt(const string & privateKeyPath, const string & inputFilePath) {
    string outputFilePath = "../decryptedFile";

    /// READ KEY
    FILE *  f = openFile(privateKeyPath, "r");
    EVP_PKEY *privKey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);

    /// READ HEAD
    FILE *input = openFile(inputFilePath, "rb");
    unsigned char iv[EVP_MAX_IV_LENGTH];
    auto *cypherName = (unsigned char *)malloc(12);
    fread(cypherName, sizeof(unsigned char), 11, input);
    cypherName[11] = '\0';

        unsigned int encryptKeyLen;
    fscanf(input, "%u", &encryptKeyLen);
    auto *encryptKey = (unsigned char *)malloc(encryptKeyLen);
    fread(encryptKey, sizeof(unsigned char), encryptKeyLen, input);

    fread(iv, sizeof(unsigned char), EVP_MAX_IV_LENGTH, input);

    /* debug info */
    printf("cypherName: %s\n", cypherName);
    printf("key: ");
    for (int i = 0; i < encryptKeyLen; i++)
        printf("%02x", encryptKey[i]);
    printf("\nIV:");
    for (unsigned char i : iv)
        printf("%02x", i);


    /// CYPHER INITIALIZATION
    const EVP_CIPHER *cipher = EVP_get_cipherbyname((const char*) cypherName);
    EVP_CIPHER_CTX *ctx;
    if (!(ctx = EVP_CIPHER_CTX_new())) exit(6);
    if (!EVP_OpenInit(ctx, cipher, encryptKey, encryptKeyLen, iv, privKey)) exit(7);


    /// DECIPHER
    FILE * output = openFile(outputFilePath, "w");

    /* decipher main part */
    unsigned char buffer[BUFFER_SIZE];
    unsigned char bufferOut[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int res, length = 0, decryptedDataLength = 0;
    while ((res = static_cast<int>(fread(buffer, sizeof(unsigned char), BUFFER_SIZE, input))) > 0) {
        if (!EVP_OpenUpdate(ctx, bufferOut, &decryptedDataLength, buffer, res)) exit(8);
        fwrite(bufferOut, sizeof(unsigned char), static_cast<size_t>(decryptedDataLength), output);
        length += decryptedDataLength;
    }

    /* decipher last block */
    if (!EVP_OpenFinal(ctx, bufferOut, &decryptedDataLength)) exit(9);
    fwrite(bufferOut, sizeof(unsigned char), static_cast<size_t>(decryptedDataLength), output);
    length += decryptedDataLength;


    printf("\ntotal length: %d", length);

    fclose(input);
    fclose(output);
    free(cypherName);
    free(encryptKey);
}

/// *********** MAIN ******************
int main(int argc, char *argv[]) {

   // if(argc != 1 || argv[1] != "e"&& argv[1] != "d") {
   //     printf("usage 1: \"e {publicKeyPath} {inputFileName}\"\n"
   //            "usage 2: \"d {privateKeyPath} {inputFileName}\"\n");
   // }

    //if(argv[1] == "e") {
        string publicKeyPath = "../pubkey.pem";
        string inputFilePath = "../inputFile";

        encrypt(publicKeyPath, inputFilePath);
        printf("\n***ENCRYPTION DONE***\n\n");
   // }
   // else {
        string privateKeyPath = "../privkey.pem";
        string inFilePath = "../encryptedFile";
        decrypt(privateKeyPath,inFilePath);
    printf("\n***DECRYPTION DONE***\n");

  //  }


}