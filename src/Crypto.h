#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int PRF(unsigned char* key,unsigned char* data,unsigned char* PRF_output, size_t key_len, size_t data_len, size_t output_len);
int sha256(unsigned char* data, unsigned char* output, size_t data_len, size_t output_len);
int randomString(unsigned char* randomString_output,size_t output_len);

#endif /* CRYPTO_H */
