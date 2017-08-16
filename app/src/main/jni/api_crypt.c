#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "des.h"
#include "encrypt_check.h"


//const unsigned char key[8] = { 58, 50, 42, 34, 26, 18, 10, 2};

jstring Chars_To_Jstring(JNIEnv *env, char *buf)
{
    jclass strClass = (*env)->FindClass(env,"java/lang/String");
    jmethodID ctorID = (*env)->GetMethodID(env,strClass, "<init>", "([BLjava/lang/String;)V");
    jbyteArray bytes = (*env)->NewByteArray(env,strlen(buf));
    (*env)->SetByteArrayRegion(env,bytes, 0, strlen(buf), (jbyte*)buf);
    jstring encoding = (*env)->NewStringUTF(env,"utf-8");
    return (jstring)(*env)->NewObject(env, strClass, ctorID, bytes, encoding);
}

JNIEXPORT jstring JNICALL
Java_com_pingan_apicrypt_ApiCrypt_decrypt(JNIEnv *env, jclass type, jstring dec_) {
    const char *dec = (*env)->GetStringUTFChars(env, dec_, 0);

    if (dec == NULL || strlen(dec) <= 0) {
        return NULL;
    }

    unsigned char *pBuffer = NULL;

    //简单解密
    //char *returnValue = (char *) malloc(sizeof(dec));
    //simpleDec(dec, returnValue);
    //const char *returnValue = NULL;

    //DES解密
    des_decipher((const unsigned char *) dec, &pBuffer);

    //AES解密
    //aes128_cbc_decrypt(dec, NULL, &pBuffer);

    (*env)->ReleaseStringUTFChars(env, dec_, dec);

    jstring ret = (*env)->NewStringUTF(env, (char *)pBuffer);

    free(pBuffer);
    return ret;
}

JNIEXPORT jstring JNICALL
Java_com_pingan_apicrypt_ApiCrypt_encrypt(JNIEnv *env, jclass type, jstring enc_) {
    const char *enc = (*env)->GetStringUTFChars(env, enc_, 0);

    if (enc == NULL || strlen(enc) <= 0) {
        return NULL;
    }

    unsigned char *pBuffer = NULL;

    //简单异或加密
    //simpleEnc(enc, returnValue);

    //DES加密
    des_encipher((const unsigned char *) enc, &pBuffer);

    //AES加密
//    aes128_cbc_encrypt(enc, NULL, &pBuffer);

    (*env)->ReleaseStringUTFChars(env, enc_, enc);

    jstring ret = (*env)->NewStringUTF(env, (char *)pBuffer);

    free(pBuffer);
    return ret;
}