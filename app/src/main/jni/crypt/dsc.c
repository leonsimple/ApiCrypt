/*=======================================================================
dsCrypt v1.00-CLI (command-line interface)               rev: 2004.09.17

Copyright (c) 2004 Dariusz Stanislawek
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
=========================================================================

dsCrypt is a file encryption program.

Cipher: AES (Rijndael)
Mode: CBC
Key: 256 bits
IV: 16 bytes
Max File Size: 2GB
Cipher File Structure:
[cipherdata] + [padding <= 16 bytes] + [IV = 16 random bytes]

Change Log
----------
v1.00
- released 2004.09.17

Website
-------
http://www.ozemail.com.au/~nulifetv/freezip/freeware/
http://freezip.cjb.net/freeware/
                                                  freezip(at)bigfoot,com
=======================================================================*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "rijndael-api-fst.h"

#define BLOCKSIZE  (64 * 1024) // the optimal buffer size for sequential I/O on Windows NT/2k/XP


void gen_iv(unsigned char *buf, int size)
{
    while(--size >= 0) buf[size] += rand();
}


char msg1[] = "%s: The data is invalid\n";
char msg2[] = "%s: The file exists\n";


/*=====================================================================*/


int crypt(char *keyfile, int encrypt, char *src, char *dst)
{
    keyInstance keyInst;
    cipherInstance cipherInst;
    FILE *fkey, *fsrc, *fdst;
    unsigned char keyMaterial[MAX_KEY_SIZE], membuf[BLOCKSIZE + 32], initiv[MAX_IV_SIZE];
    int i, fsize, sread, status = 1, round = 0;

    if((fdst = fopen(dst, "r")) != NULL) // check if file exists
    {
        printf(msg2, dst);
        fclose(fdst);
        return 1;
    }

    if((fkey = fopen(keyfile, "rb")) == NULL)
    {
        perror(keyfile);
        return 1;
    }

    if((fsrc = fopen(src, "rb")) == NULL)
    {
        perror(src);
        goto quit;
    }

    if((fdst = fopen(dst, "wb")) == NULL)
    {
        perror(dst);
        goto quit;
    }


    if(MAX_KEY_SIZE != fread(keyMaterial, 1, MAX_KEY_SIZE + 1, fkey))
    {
        printf(msg1, keyfile);
        goto quit;
    }


    if(encrypt)
    {
        for(i = (BLOCKSIZE / 4) - 1; i >= 0; i--) sread += ((int*)membuf)[i];
        srand(sread ^ time(NULL));
        gen_iv(cipherInst.IV, MAX_IV_SIZE);
        memcpy(initiv, cipherInst.IV, MAX_IV_SIZE);
        fseek(fsrc, 0, SEEK_END);
    }
    else
    {
        fseek(fsrc, - MAX_IV_SIZE, SEEK_END);
        if(MAX_IV_SIZE != fread(cipherInst.IV, 1, MAX_IV_SIZE, fsrc))
        {
            printf(msg1, src);
            goto quit;
        }
    }
    fsize = ftell(fsrc);
    rewind(fsrc);
    if(!encrypt && (fsize < 32 || fsize % 16))
    {
        printf(msg1, src);
        goto quit;
    }


    if(0 >= makeKey(&keyInst, encrypt ? DIR_ENCRYPT : DIR_DECRYPT, MAX_KEY_SIZE * 4, keyMaterial))
    {
        printf(msg1, keyfile);
        goto quit;
    }
    cipherInst.mode = MODE_CBC;


    while((sread = fread(membuf, 1, BLOCKSIZE, fsrc)) > 0)
    {
        fsize -= sread;
        if(encrypt)
        {
            if(fsize)
            {
                blockEncrypt(&cipherInst, &keyInst, membuf, sread, membuf);
                memcpy(cipherInst.IV, membuf + BLOCKSIZE - MAX_IV_SIZE, MAX_IV_SIZE);
            }
            else sread = padEncrypt(&cipherInst, &keyInst, membuf, sread, membuf);
        }
        else
        {
            if(sread == BLOCKSIZE && fsize > 32)
                blockDecrypt(&cipherInst, &keyInst, membuf, sread, membuf);
            else
            {
                if(fsize)
                {
                    if(fsize != fread(membuf + BLOCKSIZE, 1, fsize, fsrc))
                    {
                        printf(msg1, src);
                        goto quit;
                    }
                    sread += fsize;
                }
                if(0 >= (sread = padDecrypt(&cipherInst, &keyInst, membuf, sread - MAX_IV_SIZE, membuf)))
                {
                    printf(msg1, src);
                    goto quit;
                }
            }
        }
        if(sread != fwrite(membuf, 1, sread, fdst))
        {
            printf(msg1, dst);
            goto quit;
        }
        round++;
        if(!(round % 16)) printf(".");
    }


    if(encrypt)
    {
        if(MAX_IV_SIZE != fwrite(initiv, 1, MAX_IV_SIZE, fdst))
        {
            printf(msg1, dst);
            goto quit;
        }
    }
    printf("DONE %uMB\n", round / 16);
    status = 0; // SUCCESS

quit:
    fclose(fkey);
    if(fsrc) fclose(fsrc);
    if(fdst)
    {
        fclose(fdst);
        if(status) remove(dst);
    }
    if(!encrypt) memset(membuf, 0, sizeof(membuf)); // sensitive data memory cleanup
    memset(keyMaterial, 0, sizeof(keyMaterial));
    makeKey(&keyInst, DIR_ENCRYPT, MAX_KEY_SIZE * 4, keyMaterial);
    return status;
}


/*=====================================================================*/


int main(int argc, char *argv[])
{
    if(argc == 5)
    {
        *argv[2] = toupper(*argv[2]);
        switch (*argv[2])
        {
            case 'E':
            case 'D':
            return crypt(argv[1], *argv[2] == 'E', argv[3], argv[4]);
        }
    }
    printf("dsCrypt v1.00-CLI, Freeware - use at your own risk.\n"
           "(c)2004 Dariusz Stanislawek, http://freezip.cjb.net/freeware/\n\n"
           "Usage: dsc keyfile e|d source destination\n\n"
           "Keyfile must contain 64 hexadecimal bytes.\n"
           "Encryption example: dsc a:\\my.key e d:\\x\\data.zip data.enc\n"
           "Decryption example: dsc my.key d data.enc c:\\tmp\\data.zip\n");
    return 1;
}

