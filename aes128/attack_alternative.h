#ifndef __ATTACK_ALT_H__
#define __ATTACK_ALT_H__
#include "aes-128_enc_alternative.h"
#include <stdint.h>
#define LAMBDA 40
uint8_t partial_dec_alternative(uint16_t key_byte, uint16_t state_byte);
int detect_false_positive_alternative(uint8_t possible_keys[AES_128_KEY_SIZE][256]);
#endif