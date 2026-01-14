#ifndef AES_CORE_H
#define AES_CORE_H

#include <stdint.h>
#define SHIFT_LEFT  0 // Cifrar
#define SHIFT_RIGHT 1 // Decifrar
void encrypt_block(const uint8_t *input, uint8_t *output, const uint32_t *round_keys, const uint8_t *box, int number_of_rounds);
void decrypt_block(const uint8_t *input, uint8_t *output, const uint32_t *round_keys, const uint8_t *inv_box, int number_of_rounds);
void key_expansion(const uint8_t *main_key, uint32_t *round_keys, const uint8_t *box, int key_length);
#endif