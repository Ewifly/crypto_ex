#include "crypto_utils.h"
#include <sys/random.h>

int print_block(uint8_t block[AES_BLOCK_SIZE])
{
    for (int i = 0; i < AES_BLOCK_SIZE / 4; i++)
    {
        for (int j = 0; j < AES_BLOCK_SIZE / 4; j++)
        {
            printf("%02X ", block[i + j * 4]);
        }
        printf("\n");
    }
    printf("\n");
    return 0;
}

int is_equal_block(uint8_t block1[AES_BLOCK_SIZE], uint8_t block2[AES_BLOCK_SIZE])
{
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        if (block1[i] != block2[i])
        {
            return 0;
        }
    }
    return 1;
}

int copy_block(uint8_t block1[AES_BLOCK_SIZE], uint8_t block2[AES_BLOCK_SIZE])
{
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        block1[i] = block2[i];
    }
    return 0;
}

int wipe_block(uint8_t block[AES_BLOCK_SIZE])
{
    for (int i = 0; i < AES_128_KEY_SIZE; i++)
    {
        block[i] = 0;
    }
    return 0;
}

int xor_block(uint8_t block1[AES_BLOCK_SIZE], uint8_t block2[AES_BLOCK_SIZE])
{
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        block1[i] ^= block2[i];
    }
    return 0;
}

int init_lambda(uint8_t lambda[256][AES_BLOCK_SIZE], uint8_t l)
{
    uint8_t dumb[AES_BLOCK_SIZE] = {l, l, l, l, l, l, l, l, l, l, l, l, l, l, l, l};
    for (int i = 0; i < 256; i++)
    {
        copy_block(lambda[i], dumb);
        lambda[i][0] = i;
    }
    return 0;
}

int keyFunction(uint8_t block[AES_BLOCK_SIZE], const uint8_t key1[AES_128_KEY_SIZE], const uint8_t key2[AES_128_KEY_SIZE])
{
    /*Copy Input Block */
    uint8_t block2[AES_BLOCK_SIZE];
    copy_block(block2, block);
    /*Apply 3 full rouint print_block(uint8_t block[AES_BLOCK_SIZE])nds of AES to the two blocks separately with their respective key*/
    aes128_enc(block, key1, 3, 1);
    aes128_enc(block2, key2, 3, 1);
    /*Xor the two resultant block to get the final result*/
    xor_block(block, block2);
    return 0;
}

int generate_key(uint8_t key[AES_128_KEY_SIZE])
{
    int randomData = getrandom(key, AES_128_KEY_SIZE, GRND_NONBLOCK);
    return randomData;
}
