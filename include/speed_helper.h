#ifndef SPEED_HELPER_H
#define SPEED_HELPER_H

#include <stddef.h> 
#include <stdint.h> 

void aes_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len, uint32_t *base_round_keys, int number_of_rounds);
void aes_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, uint32_t *base_round_keys, int number_of_rounds);

void t_aes_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, uint32_t *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word);
void t_aes_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len, uint32_t *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word);

void t_aes_ni_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, __m128i *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word);
void t_aes_ni_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len,__m128i *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word);

int xts_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, const uint8_t *key, int key_length_bits);
int xts_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len, const uint8_t *key, int key_length_bits);
#endif
