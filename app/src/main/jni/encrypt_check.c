#include <string.h>
#include "encrypt_check.h"
#include "crypt/rijndael-api-fst.h"
#include "md5.h"

unsigned char initKey[] = { 0x70, 0x69, 0x6e, 0x67, 0x61, 0x6e, 0x31, 0x32, 0x00 };

//默认普通加密密钥
unsigned char defaultKey[] = {0x6b, 0x61, 0x6e, 0x67, 0x77, 0x65, 0x69, 0x5f, 0x70, 0x69, 0x6e, 0x67, 0x61, 0x6e, 0x31, 0x00 };

//IV容器：ujhfwe9ihv0as89w
//d9c17ba62f9242a1
unsigned char iv[]  = { 0x75, 0x6a, 0x68, 0x66, 0x77, 0x65, 0x39, 0x69, 0x68, 0x76, 0x30, 0x61, 0x73, 0x38, 0x39, 0x77, 0x00 };


int create_sign(const char *pOrigin, const char *pParam, const char *pSecurity, char *pMD5)
{
    char originKey[] = "origin=";
    char paramKey[] = "&param=";
    char securityKey[] = "&security=";
    char key[] = "&key=";
    int nTotalLen = 0;
    int nOriginLen = strlen(originKey);

    if (pOrigin != NULL && strlen(pOrigin) > 0)//值为空不参与签名
    {
        nTotalLen = nTotalLen + nOriginLen + strlen(pOrigin);
    }

    int nParamLen = strlen(paramKey);

    if (pParam != NULL && strlen(pParam) > 0)//值为空不参与签名
    {
        nTotalLen = nTotalLen + nParamLen + strlen(pParam);
    }

    int nSecurityLen = strlen(securityKey);

    if (pSecurity != NULL && strlen(pSecurity) > 0)//值为空不参与签名
    {
        nTotalLen = nTotalLen + nSecurityLen + strlen(pSecurity);
    }

    int nKeyLen = strlen(key) + strlen(initKey);

    nTotalLen = nTotalLen + nKeyLen;

    char *pBuffer = (char *)malloc(nTotalLen + 1);
    memset(pBuffer, 0, nTotalLen + 1);

    if (pOrigin != NULL && strlen(pOrigin) > 0)
    {
        memcpy(pBuffer + strlen(pBuffer), originKey, strlen(originKey));
        memcpy(pBuffer + strlen(pBuffer), pOrigin, strlen(pOrigin));
    }

    if (pParam != NULL && strlen(pParam) > 0)
    {
        memcpy(pBuffer + strlen(pBuffer), paramKey, strlen(paramKey));
        memcpy(pBuffer + strlen(pBuffer), pParam, strlen(pParam));
    }

    if (securityKey != NULL && strlen(securityKey) > 0)
    {
        memcpy(pBuffer + strlen(pBuffer), securityKey, strlen(securityKey));
        memcpy(pBuffer + strlen(pBuffer), pSecurity, strlen(pSecurity));
    }

    memcpy(pBuffer + strlen(pBuffer), key, strlen(key));
    memcpy(pBuffer + strlen(pBuffer), initKey, strlen(initKey));

    MD5((unsigned char*)pBuffer, strlen(pBuffer), pMD5);
    free(pBuffer);

    return strlen(pMD5);
}

//AES加密
int aes128_cbc_encrypt(const char *pPlaintext, const  char *pKey, unsigned char **pBuffer)
{
    int nPlaintextLen = strlen(pPlaintext);//明文长度
    int nCiphertextLen =  nPlaintextLen ;

    int remainders = nPlaintextLen % 16;
    if (remainders)//需要填充
    {
        nCiphertextLen = nCiphertextLen + (16 -  remainders);//密文长度，加了填充位
    }
    else
    {
        nCiphertextLen = nCiphertextLen + 16;//长度为16的倍数时也需要填充
    }

    unsigned char *pCiphertext = (unsigned char *)malloc(nCiphertextLen);
    memset(pCiphertext, 0, nCiphertextLen);

    //填充后明文密文的长度一致
    unsigned char *pInput = (unsigned char *)malloc(nPlaintextLen);
    memset(pInput, 0, nPlaintextLen);
    memcpy(pInput, pPlaintext, nPlaintextLen);

    //生成128位密钥
    char *pBaseKey = NULL;
    if (pKey == NULL)
    {
        pBaseKey = defaultKey;
    }
    else
    {
        pBaseKey = (unsigned char *)pKey;
    }
    char cMD5[32 + 1] = {0};
    int nKeyLen = 0;
    unsigned char *p = pBaseKey;
    while(1)
    {
        if (*p == 0)
        {
            break;
        }
        else
        {
            nKeyLen++;
            p++;
        }
    }

    MD5(pBaseKey, nKeyLen, cMD5);
    unsigned char key[16 + 1] = {0};
    memcpy(key, cMD5 + 8, 16);

    keyInstance keyInst = {0};
    cipherInstance cipherInst = {0};
    unsigned char  keyMaterial[ENCRYPT_KEY_LEN * 2 + 1] = {0};
    int n = 0;
    for (n = 0; n < ENCRYPT_KEY_LEN/8; n++) {
        sprintf (&keyMaterial[2*n], "%02X", key[n]);
    }

    if (makeKey(&keyInst, DIR_ENCRYPT, ENCRYPT_KEY_LEN, keyMaterial) <= 0)
    {
        return 0;
    }


    //加密
    //cipherInit(&cipherInst, MODE_CBC, iv);
    memcpy(cipherInst.IV, iv, 16);
    cipherInst.mode = MODE_CBC;
    padEncrypt(&cipherInst, &keyInst, pInput, nPlaintextLen, pCiphertext);

    //BASE64编码
    int mBase64Len = (nCiphertextLen * 4) / 3  + 4;
    *pBuffer = (unsigned char *)malloc(mBase64Len);
    memset(*pBuffer, 0, mBase64Len);
    base64_encode(pCiphertext, *pBuffer, nCiphertextLen, 0);

    free(pCiphertext);
    free(pInput);

    return 1;

}

//AES解密
int aes128_cbc_decrypt(const char *pCiphertext, const  char *pKey, unsigned char **pBuffer)
{
    //BASE64解码
    int mBase64Len = 3 * strlen(pCiphertext) / 4 + 1;
    unsigned char *pBase64Buffer = (unsigned char *)malloc(mBase64Len);
    memset(pBase64Buffer, 0, mBase64Len);
    int nCiphertextLen = base64_decode(pCiphertext, pBase64Buffer, strlen(pCiphertext));

    //生成128位密钥
    unsigned char *pBaseKey = NULL;
    if (pKey == NULL)
    {
        pBaseKey = defaultKey;
    }
    else
    {
        pBaseKey = (unsigned char *)pKey;
    }
    char cMD5[32 + 1] = {0};
    int nKeyLen = 0;
    unsigned char *p = pBaseKey;
    while(1)
    {
        if (*p == 0)
        {
            break;
        }
        else
        {
            nKeyLen++;
            p++;
        }
    }

    MD5(pBaseKey, nKeyLen, cMD5);
    unsigned char key[16 + 1] = {0};
    memcpy(key, cMD5 + 8, 16);

    //解密
    keyInstance keyInst = {0};
    cipherInstance cipherInst = {0};
    unsigned char  keyMaterial[ENCRYPT_KEY_LEN * 2 + 1] = {0};
    int n = 0;
    for (n = 0; n < ENCRYPT_KEY_LEN/8; n++) {
        sprintf (&keyMaterial[2*n], "%02X", key[n]);
    }

    if (makeKey(&keyInst, DIR_DECRYPT, ENCRYPT_KEY_LEN, keyMaterial) <= 0)
    {
        return 0;
    }

    //cipherInit(&cipherInst, MODE_CBC, iv);
    memcpy(cipherInst.IV, iv, 16);
    cipherInst.mode = MODE_CBC;
    *pBuffer = (unsigned char *)malloc(nCiphertextLen + 1);
    memset(*pBuffer, 0, nCiphertextLen + 1);

    padDecrypt(&cipherInst, &keyInst, pBase64Buffer, nCiphertextLen, *pBuffer);
    free(pBase64Buffer);
    return 1;
}

int encrypt_network_data(const char *pPlaintext, unsigned char **pBuffer)
{
    return aes128_cbc_encrypt(pPlaintext,initKey, pBuffer);
}

int decrypt_network_data(const char *pPlaintext, unsigned char **pBuffer)
{
    return aes128_cbc_decrypt(pPlaintext,initKey, pBuffer);
}