/*
Ewi
RC4 algorithm
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "RC4.h"


int main(int argc, char *argv[]){

    if(argc < 3) {
        printf("Usage : %s <KEY> <PLAINTEXT>", argv[0]);
        return -1;
    }
    char *ciphertext = malloc(sizeof(int) * strlen(argv[2]));

    encrypt(argv[1], argv[2], ciphertext);
    for (u_int32_t i = 0; i < strlen(argv[2]); i++){
        printf("%02hhX", ciphertext[i]);
    }
    return 0;
}