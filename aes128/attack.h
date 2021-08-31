#ifndef __ATTACK_H__
#define __ATTACK_H__
#include "aes-128_enc.h"
#include <stdint.h>
#define LAMBDA 40
uint8_t partial_dec(uint16_t key_byte, uint16_t state_byte);
int detect_false_positive(uint8_t possible_keys[AES_128_KEY_SIZE][256]);
#endif