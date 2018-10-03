#include <iostream>
#include <openssl/evp.h>
#include <cstring>
#include <openssl/err.h>

const EVP_CIPHER *cipher;

int encrypt(unsigned char *plaintxt, int plaintxt_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertxt) {
    EVP_CIPHER_CTX *ctx;

    int ciphertxt_len = 0, len = 0;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) exit(1);

    /* Initialise the encryption operation.
     * IMPORTANT - ensure you use a key and IV size appropriate for your cipher
     * AES 256 (i.e. a 256 bit key). The  IV size for *most* modes same size block size. For AES - 128 bits
     * */
    if (1 != EVP_EncryptInit_ex(ctx, cipher, nullptr, key, iv)) exit(2);

    /* Provide the message to be decrypted, and obtain the plaintext output.
    * EVP_EncryptUpdate can be called multiple times if necessary
    */
    if (1 != EVP_EncryptUpdate(ctx, ciphertxt, &len, plaintxt, plaintxt_len)) exit(3);
    ciphertxt_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written. – dokončení šifrování posledního bloku
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertxt + len, &len)) exit(4);
    ciphertxt_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertxt_len;
}

int decrypt(unsigned char *ciphertxt, int ciphertxt_len, unsigned char *key, unsigned char *iv, unsigned char *plaintxt) {
    EVP_CIPHER_CTX *ctx;

    int plaintext_len = 0, len = 0;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) exit(5);

    /* Initialise the decryption operation. IMPORTANT - ensure you use a keyand IV size appropriate for your cipher
     * AES 256 (i.e. a 256 bit key). The IV size for *most* modes is the same as the block size.
     * For AES this is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, cipher, nullptr, key, iv)) exit(6);

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintxt, &len, ciphertxt, ciphertxt_len)) exit(7);
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintxt + len, &len)) {
        ERR_print_errors_fp(stderr);
        exit(8);

    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

uint32_t getZac(const unsigned char *s) {
    return (uint32_t) (((uint32_t) s[13]) << 24) | (((uint32_t) s[12]) << 16) | (((uint32_t) s[11]) << 8) |
           ((uint32_t) s[10]);
}

void editNewLength(unsigned char *plaintxt, int newLength) {
    for (int i = 3, j = 0; i < 7; ++i, j += 8)
        plaintxt[i] = (unsigned char) newLength >> j;
}

void writeImage(const char *path, unsigned char *hdr, uint32_t hdr_len, unsigned char *ciphertxt, int ciphertxt_len) {
    FILE *pFile = fopen(path, "wb");
    if (!pFile) {
        fputs("File error", stderr);
        exit(1);
    }

    fwrite(hdr, sizeof(unsigned char), hdr_len, pFile);

    fwrite(ciphertxt, sizeof(unsigned char), (unsigned int) ciphertxt_len, pFile);
    fclose(pFile);
}

uint32_t readImage(const char *path, unsigned char **buffer) {
    uint32_t lSize;

    FILE *pFile;
    size_t result;

    pFile = fopen(path, "rb");
    if (!pFile) {
        fputs("File error", stderr);
        exit(1);
    }

    // obtain file size:
    fseek(pFile, 0, SEEK_END);
    lSize = (uint32_t) ftell(pFile);
    rewind(pFile);

    // allocate memory to contain the whole file:
    *buffer = (unsigned char *) malloc(sizeof(unsigned char) * lSize);
    if (!(*buffer)) {
        fputs("Memory error", stderr);
        exit(2);
    }

    // copy the file into the buffer:
    result = fread(*buffer, 1, (size_t) lSize, pFile);
    if (result != lSize) {
        fputs("Reading error", stderr);
        exit(3);
    }
    // terminate
    fclose(pFile);

    return lSize;
}


int main() {
    /*************CONFIGURATION*************************************/
    /* file name */
    std::string filename = "Mad_scientist";

    /* base path */
    std::string filenameIn = "../srcobr/" + filename + ".bmp";

    /* operation mode of AES 256 */
    std::string mode = "cbc";

    /* A 256 bit key */
    auto *key = (unsigned char *) "01234567890123456789012345678901";

    /* A 128 bit IV */
    auto *iv = (unsigned char *) "0123456789012345";
    /***************************************************************/

    std::string filenameDecryptedOut;
    std::string filenameEncryptedOut;

    /* Init desired cipher  */
    if (mode == "ecb") {
        cipher = EVP_aes_256_cbc();
        filenameDecryptedOut = "../srcobr/" + filename + "_aes_256_cbc_dec.bmp";
        filenameEncryptedOut = "../srcobr/" + filename + "_aes_256_cbc.bmp";
    } else {
        cipher = EVP_aes_256_ecb();
        filenameDecryptedOut = "../srcobr/" + filename + "_aes_256_ecb_dec.bmp";
        filenameEncryptedOut = "../srcobr/" + filename + "_aes_256_ecb.bmp";
    }

    /// ****************  ENCRYPT  ***************** ///
    {
        /* Message to be encrypted */
        unsigned char *plaintxt;
        unsigned int plaintxt_len = readImage(filenameIn.c_str(), &plaintxt);

        /* Find end of the header */
        uint32_t header_len = getZac(plaintxt);

        /* Buffer for ciphertext. !! may be longer than the plaintext !! */
        auto *ciphertxt = (unsigned char *) malloc(sizeof(unsigned char) * plaintxt_len * 2);

        /* Encrypt the plaintext  !! skip header !!  */
        int ciphertxt_len = encrypt(plaintxt + header_len, plaintxt_len - header_len, key, iv, ciphertxt);

        /* Edit new file length in the header */
        editNewLength(plaintxt, ciphertxt_len + 14);

        /* Write to the file */
        writeImage(filenameEncryptedOut.c_str(), plaintxt, header_len, ciphertxt, ciphertxt_len);

        /*Clean up*/
        free(ciphertxt);
    }

    /// ****************  DECRYPT  ***************** ///
    {
        /* Message to be decrypted */
        unsigned char *ciphertxt;
        unsigned int ciphertxt_len = readImage(filenameEncryptedOut.c_str(), &ciphertxt);

        /* Find end of the header */
        uint32_t header_len = getZac(ciphertxt);

        /* Buffer for decypheredtext ? may be longer than the cyphered text ? */
        auto *decypheredtxt = (unsigned char *) malloc(sizeof(unsigned char) * ciphertxt_len * 2);

        /* Decrypt the ciphertext !! skip header !! */
        int decryptedtext_len = decrypt(ciphertxt + header_len, ciphertxt_len - header_len, key, iv, decypheredtxt);

        /* Edit new file length in the header */
        editNewLength(ciphertxt, decryptedtext_len + 14);

        /* Write to the file */
        writeImage(filenameDecryptedOut.c_str(), ciphertxt, header_len, decypheredtxt, decryptedtext_len);

        /* Clean up */
        free(decypheredtxt);
    }

    return 0;
}
