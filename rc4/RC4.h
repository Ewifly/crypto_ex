#ifndef __RC4_H__
#define __RC4_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define SBOXSIZE 256

static void swap_int(unsigned char *a, unsigned char *b){
    int32_t tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA(char *key, unsigned char *Sbox){
    /*
    Key Sheduling Algorithm for RC4
    */
   int32_t lenkey = strlen(key);
   int16_t j = 0;

   for (int16_t i = 0; i < SBOXSIZE; i++){
       Sbox[i] = i;
   }
   for (int16_t i = 0; i < SBOXSIZE; i++){
       j = (j + Sbox[i] + key[i % lenkey]) % SBOXSIZE;
       swap_int(&Sbox[i], &Sbox[j]);
   }
}

static int PRGA(unsigned char *Sbox, char *plaintext, unsigned char *ciphertext){
    /*
    Pseudo Randome Generation Algorithme
    */
    int16_t i = 0, j = 0;

    for (u_int32_t k = 0; k < strlen(plaintext); k++){
        i = ( i + 1 ) % SBOXSIZE;
        j = ( j + Sbox[i]) % SBOXSIZE;
        swap_int(&Sbox[i], &Sbox[j]);

        ciphertext[k] = Sbox[(Sbox[i] + Sbox[j]) % SBOXSIZE] ^ plaintext[k]; 
    }
}


int encrypt(char * key, char *plaintext, unsigned char * ciphertext){
    unsigned char Sbox[SBOXSIZE];
    KSA(key, Sbox);
    PRGA(Sbox, plaintext, ciphertext);

    return 0;
}
#endif
