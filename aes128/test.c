
#include "aes-128_enc.h"

/*==========================#include "crypto_utils.h"========================================================================================*/
int test_1()
{
	uint8_t test_key[AES_128_KEY_SIZE] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
										  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	uint8_t next_key[AES_128_KEY_SIZE];
	uint8_t prev_key[AES_128_KEY_SIZE];
	int round = 0;

	wipe_block(prev_key);
	wipe_block(next_key);
	print_block(test_key);
	next_aes128_round_key(test_key, next_key, round);
	prev_aes128_round_key(next_key, prev_key, round);

	switch (is_equal_block(prev_key, test_key))
	{
	case 1:
		printf("test 1 passed \n");
		break;

	default:
		printf("test 1 failed\n");
		break;
	}
	return 0;
}

int test_2()
{
	uint8_t key1[AES_128_KEY_SIZE] = {0xB0, 0x0B, 0x2A, 0x3C, 0xFF, 0xDD, 0x13, 0x55, 0x67, 0xA2, 0xCC, 0x04, 0x67, 0xAA, 0xFF, 0x43};
	uint8_t key2[AES_128_KEY_SIZE] = {0X62, 0xC2, 0xEE, 0xF3, 0x22, 0x17, 0x88, 0x9A, 0x99, 0x43, 0xEE, 0xF3, 0x11, 0x54, 0x83, 0xB1};
	uint8_t lambda[256][16];
	init_lambda(lambda, 0);
	for (int i = 0; i < 256; i++)
	{
		keyFunction(lambda[i], key1, key2);
	}
	/*verify if the xored results give 0*/
	uint8_t result[AES_BLOCK_SIZE];
	copy_block(result, lambda[0]);
	for (int i = 1; i < 256; i++)
	{
		xor_block(result, lambda[i]);
	}
	for (int i = 0; i < AES_BLOCK_SIZE; i++)
	{
		if (result[i] != 0)
		{
			printf("test 2 failed\n");
			return 0;
		}
	}
	printf("test 2 passed \n");
	return 0;
}

int main()
{
	int t1 = test_1();
	int t2 = test_2();
	return 0;
}