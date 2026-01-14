#ifndef T_AES_SW_H
#define T_AES_SW_H

#include <stdint.h>
int process_t_aes_encryption(uint32_t *base_round_keys, uint8_t *tweak_key,int key_length);
int process_t_aes_decryption(uint32_t *base_round_keys, uint8_t *tweak_key,int key_length);
#endif