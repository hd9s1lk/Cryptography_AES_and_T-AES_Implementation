#ifndef AES_NI_CORE_H
#define AES_NI_CORE_H

#include <stdint.h>
#include <immintrin.h> 

void key_expansion_ni(const uint8_t *key_bytes, __m128i *key_schedule, int key_length);
void encrypt_block_ni(const uint8_t *input, uint8_t *output, const __m128i *key_schedule, int num_rounds);
void decrypt_block_ni(const uint8_t *input, uint8_t *output, const __m128i *key_schedule, int num_rounds);

#endif 