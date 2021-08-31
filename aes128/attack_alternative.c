#include "attack_alternative.h"
#include "crypto_utils_alternative.h"

uint8_t partial_dec_alternative(uint16_t key_byte, uint16_t state_byte)
{
    return (Sinv_alternative[state_byte ^ key_byte]);
}

int detect_false_positive_alternative(uint8_t possible_keys[AES_128_KEY_SIZE][256])
/*return true if two values of a byte are possible within a single byte*/
{
    uint8_t count;
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
    {
        count = 0;
        for (int j = 0; j < 256; j++)
        {
            count += possible_keys[i][j];
            if (count > 1)
                return 1;
        }
    }
    return 0;
}

int main()
{
    uint8_t guessed_key[AES_128_KEY_SIZE];

    uint8_t key[AES_128_KEY_SIZE];
    generate_key_alternative(key);

    uint16_t i, j, k, l;
    uint8_t lambda_set[256][AES_BLOCK_SIZE];
    uint8_t possible_keys[AES_128_KEY_SIZE][256];

    for (i = 0; i < AES_128_KEY_SIZE; i++)
    {
        for (j = 0; j < 256; j++)
        {
            possible_keys[i][j] = 1;
        }
    }
    uint8_t reversed_byte;
    uint16_t sum;
    int8_t pass = 0;
    int falsePov;
    do
    {
        /*
         generate the l lambda set
        */
        init_lambda(lambda_set, pass);
        for (i = 0; i < 256; i++)
        {
            aes128_enc_alternative(lambda_set[i], key, 4, 0);
        }
        for (i = 0; i < AES_BLOCK_SIZE; i++)
        {
            for (uint16_t key_byte = 0; key_byte < 256; key_byte++)
            {
                sum = 0;
                for (j = 0; j < 256; j++)
                {
                    reversed_byte = partial_dec_alternative(lambda_set[j][i], key_byte);
                    sum ^= reversed_byte;
                }
                /*case not candidate*/

                if (sum)
                {
                    possible_keys[i][key_byte] = 0;
                }
            }
        }

        falsePov = detect_false_positive_alternative(possible_keys);
        if (falsePov)
        {
            printf("false positive detected at %d th attempt, retrying... \n", pass + 1);
        }
        pass++;

    } while ((pass < LAMBDA) && falsePov);

    if (falsePov)
        return 1;
    for (i = 0; i < AES_BLOCK_SIZE; i++)
    {
        for (j = 0; j < 256; j++)
        {
            if (possible_keys[i][j])
            {
                guessed_key[i] = j;
            }
        }
    }
    printf("initial key :\n");
    print_block(key);
    printf("\n");
    uint8_t tmp_key[AES_128_KEY_SIZE];

    prev_aes128_round_key_alternative(guessed_key, tmp_key, 3);
    prev_aes128_round_key_alternative(tmp_key, guessed_key, 2);
    prev_aes128_round_key_alternative(guessed_key, tmp_key, 1);
    prev_aes128_round_key_alternative(tmp_key, guessed_key, 0);
    printf("key : \n");
    print_block(guessed_key);
    printf("\n");

    return 0;
}
