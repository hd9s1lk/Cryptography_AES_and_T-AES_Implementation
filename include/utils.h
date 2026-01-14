#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <immintrin.h> 

void add_128_bit(uint32_t *round_keys, const uint8_t *tweak_bytes, int rk_start_word);
void increment_tweak(uint8_t *tweak);
void generate_sha256_hash(const char *password, size_t key_size_bytes, uint8_t *main_key);
void get_t_aes_parameters(int key_length, int *num_rounds, int *tweak_offset);
void add_128_bit_ni(__m128i *key_schedule, const uint8_t *tweak_key, int rk_start_word);
void generate_random_buffer(uint8_t *buffer, size_t buffer_size);

extern const uint8_t s_box[256];
extern const uint8_t inv_s_box[256];
#endif