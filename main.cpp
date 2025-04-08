#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <cstring>
#include <openssl/err.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

std::string base64_encode(const unsigned char* buffer, size_t length) {
    BIO* bmem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines
    BIO_write(b64, buffer, length);
    BIO_flush(b64);

    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(b64, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    
    BIO_free_all(b64);
    return result;
}

std::string base64_decode(const std::string& encoded) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new_mem_buf(encoded.data(), encoded.size());
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    
    char* buffer = new char[encoded.size()];
    int decodedLength = BIO_read(bmem, buffer, encoded.size());
    
    std::string result(buffer, decodedLength);
    
    delete[] buffer;
    BIO_free_all(bmem);
    
    return result;
}

std::string aes256_ecb_encrypt(const std::string& plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    int len;
    int ciphertext_len;
    
    unsigned char ciphertext[8049];
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv) != 1)
        handleErrors();
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)plaintext.c_str(), plaintext.length()) != 1)
        handleErrors();
    
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handleErrors();
    
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
//    std::cout<<"Encrypted text : "<<ciphertext<<std::endl;
//    std::cout<<"Encrypted text length : "<<ciphertext_len<<std::endl;
    return base64_encode(ciphertext, ciphertext_len);
}

std::string aes256_ecb_decrypt(const std::string& encodedCiphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    
    int len;
    int plaintext_len;
    
    std::string decodedCiphertext = base64_decode(encodedCiphertext);
    
    unsigned char plaintext[8049];
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv) != 1)
        handleErrors();
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, (unsigned char*)decodedCiphertext.c_str(), decodedCiphertext.length()) != 1)
        handleErrors();
    
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handleErrors();
    
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    
    return std::string((char*)plaintext, plaintext_len);
}

int main() {
    std::string plaintext;

    std::cout<<"Enter the Text."<<std::endl;
    std::getline(std::cin,plaintext);

    std::cout<<"Length of Plain Text : "<<plaintext.length()<<std::endl;

    // Key and IV must be 32 bytes for AES-256
    //unsigned char key[32] = "1234567890123456789012345678901";
    unsigned char key[32] = "5623986712895623906734017845128";
    unsigned char iv[AES_BLOCK_SIZE] = {0}; // Replace with your own IV
    
    // Generate a random key and IV for demonstration purposes
//    RAND_bytes(key, sizeof(key));
//    RAND_bytes(iv, sizeof(iv));
    
    // Encrypt the plaintext
    std::string encryptedText = aes256_ecb_encrypt(plaintext, key, iv);
    
    std::cout << "Encoded Text (Base64): " << encryptedText << std::endl;

    // Decrypt the ciphertext
    std::string decryptedText = aes256_ecb_decrypt(encryptedText, key, iv);
    
    std::cout << "Decrypted: " << decryptedText << std::endl;

    return 0;
}

