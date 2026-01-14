#ifndef T_AES_NI_H
#define T_AES_NI_H

#include <stdint.h>
#include <immintrin.h> 
int process_t_aes_ni_encryption(__m128i *base_round_keys, uint8_t *tweak_key,int key_length);
int process_t_aes_ni_decryption(__m128i *base_round_keys, uint8_t *tweak_key,int key_length);
#endif