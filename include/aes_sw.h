#ifndef AES_SW_H
#define AES_SW_H

#include <stdint.h>
int process_aes_encryption(uint32_t *base_round_keys, int key_length);
int process_aes_decryption(uint32_t *base_round_keys, int key_length);
#endif
