.PHONY: clean

CC    = gcc 
SRC   = attack.c crypto_utils.c aes-128_enc.c
SRC_ALT = attack_alternative.c aes-128_enc_alternative.c crypto_utils_alternative.c
SRC_TEST = test.c aes-128_enc.c crypto_utils.c
SRC_TEST_ALT = test_alternative.c aes-128_enc_alternative.c crypto_utils_alternative.c
TARGET = main
TEST = test

ALL = test main

square_attack:
	$(CC) $(SRC) -o $(TARGET)

alternative_square_attack:
	$(CC) $(SRC_ALT) -o $(TARGET)

enc_test:
	$(CC) $(SRC_TEST) -o $(TEST)

enc_test_alt:
	$(CC) $(SRC_TEST_ALT) -o $(TEST)

clean:
	rm -rf $(ALL)
