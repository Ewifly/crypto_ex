#ifndef __CRYPTO_UTILS_H__
#define __CRYPTO_UTILS_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "aes-128_enc.h"

int print_block(uint8_t block[AES_BLOCK_SIZE]);
int is_equal_block(uint8_t block1[AES_BLOCK_SIZE], uint8_t block2[AES_BLOCK_SIZE]);
int copy_block(uint8_t block1[AES_BLOCK_SIZE], uint8_t block2[AES_BLOCK_SIZE]);
int wipe_block(uint8_t block[AES_BLOCK_SIZE]);
int xor_block(uint8_t block1[AES_BLOCK_SIZE], uint8_t block2[AES_BLOCK_SIZE]);
int init_lambda(uint8_t lambda[256][AES_BLOCK_SIZE], uint8_t l);

/*
* Put in @resultBlock the result of the key function F(@key1||@key2) applied to @inputBlock (AES 3 full rounds)
*/
int keyFunction(uint8_t block[AES_BLOCK_SIZE], const uint8_t key1[AES_128_KEY_SIZE], const uint8_t key2[AES_128_KEY_SIZE]);
int generate_key(uint8_t key[AES_128_KEY_SIZE]);
#endif