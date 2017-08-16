#include <stdlib.h>
#include <stdio.h>
#include "md5.h"
#include "base64.h"
#include "crypt/rijndael-api-fst.h"

#define ENCRYPT_KEY_LEN 128

//创建签名
int create_sign(const char *pOrigin, const char *pParam, const char *pSecurity, char *pMD5);

//AES加密
int aes128_cbc_encrypt(const char *pPlaintext, const  char *pKey, unsigned char **pBuffer);

//AES解密
int aes128_cbc_decrypt(const char *pCiphertext, const  char *pKey, unsigned char **pBuffer);

//加密网络数据
int encrypt_network_data(const char *pPlaintext, unsigned char **pBuffer);

//解密网络数据
int decrypt_network_data(const char *pPlaintext, unsigned char **pBuffer);