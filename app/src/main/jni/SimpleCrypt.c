//
// Created by kangwei on 2017-8-14.
// 异或加密解密
//

#include "SimpleCrypt.h"
#include <string.h>

#define shift_len  2    //字符位移

int simpleDec(const char *srcStr, char *desStr) {
    if (!srcStr || !desStr)
        return -1;
    int i;
    for (i = 0; i < strlen(srcStr); i++) {
        desStr[i] = srcStr[i] ^ 2;
        desStr[i] = desStr[i] - shift_len;
    }
    return 0;
}


int simpleEnc(const char *srcStr, char *desStr) {
    if (!srcStr || !desStr)
        return -1;
    int i;
    for (i = 0; i < strlen(srcStr); i++) {
        desStr[i] = (srcStr[i] + shift_len) ^ 2;
    }
    return 0;
}

