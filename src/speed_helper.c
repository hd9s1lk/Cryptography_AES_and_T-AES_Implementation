#include <stdio.h>
#include <string.h> 
#include <immintrin.h>
#include <wmmintrin.h> 
#include <openssl/evp.h>
#include <openssl/err.h>
#include "utils.h"
#include "aes_core.h"
#include "aes_ni_core.h"


//-----------------------------------AES-START--------------------------------------//

void aes_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len, uint32_t *base_round_keys, int number_of_rounds){
    uint8_t prev_ciphertext[16];
    uint8_t current_ciphertext[16];
    uint8_t output_plaintext[16];
    
    size_t bytes_read;
    size_t pos = 0; 


    memcpy(prev_ciphertext, ciphertext_buffer + pos, 16);
    pos += 16;

    while(1) {
        
        size_t remaining = len - pos;
        if (remaining >= 16) {
            bytes_read = 16;
        } else {
            bytes_read = remaining; 
        }

        if (bytes_read > 0) {
            memcpy(current_ciphertext, ciphertext_buffer + pos, bytes_read);
            pos += bytes_read;
        }

        if (bytes_read == 16) {
            
            decrypt_block(prev_ciphertext, output_plaintext, base_round_keys, inv_s_box, number_of_rounds);
            memcpy(plaintext_buffer + (pos - 32), output_plaintext, 16); 
            memcpy(prev_ciphertext, current_ciphertext, 16);

        } else if (bytes_read == 0) { 
            
            decrypt_block(prev_ciphertext, output_plaintext, base_round_keys, inv_s_box, number_of_rounds);
            memcpy(plaintext_buffer + (pos - 16), output_plaintext, 16);
            break; 

        } else {
            uint8_t temp_decrypted_prev[16];
            decrypt_block(prev_ciphertext, temp_decrypted_prev, base_round_keys, inv_s_box, number_of_rounds);
            uint8_t temp_reconstructed_ciphertext[16]; 
            int padding_size = 16 - bytes_read;
            memcpy(temp_reconstructed_ciphertext, current_ciphertext, bytes_read); 
            memcpy(temp_reconstructed_ciphertext + bytes_read, temp_decrypted_prev + bytes_read, padding_size);

            decrypt_block(temp_reconstructed_ciphertext, output_plaintext, base_round_keys, inv_s_box, number_of_rounds);

            memcpy(plaintext_buffer + (pos - 16 - bytes_read), output_plaintext, 16);
            memcpy(plaintext_buffer + (pos - bytes_read), temp_decrypted_prev, bytes_read);
            break;
        }
    }
}

void aes_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, uint32_t *base_round_keys,int number_of_rounds) {
    uint8_t prev_block[16];
    uint8_t current_block[16];
    uint8_t output_buffer[16];
    size_t bytes_read;
    size_t pos = 0;

    if (len < 16) {
        return; 
    }
    memcpy(prev_block, plaintext_buffer + pos, 16);
    pos += 16;

    while(1){
        size_t remaining = len - pos;
        if (remaining >= 16) {
            bytes_read = 16;
        } else {
            bytes_read = remaining;
        }

        if (bytes_read > 0) {
            memcpy(current_block, plaintext_buffer + pos, bytes_read);
            pos += bytes_read;
        }
        
        if (bytes_read == 16) {
            encrypt_block(prev_block, output_buffer, base_round_keys, s_box, number_of_rounds);
            memcpy(ciphertext_buffer + (pos - 32), output_buffer, 16);
            memcpy(prev_block, current_block, 16);

        }else if (bytes_read == 0) {
            encrypt_block(prev_block, output_buffer, base_round_keys, s_box, number_of_rounds);
            memcpy(ciphertext_buffer + (pos - 16), output_buffer, 16);
            break;
        }else {
            uint8_t temp_ciphertext[16];
            encrypt_block(prev_block, temp_ciphertext, base_round_keys, s_box, number_of_rounds);

            int padding_size = 16 - bytes_read;
            memcpy(prev_block, current_block, bytes_read);
            memcpy(prev_block + bytes_read, temp_ciphertext + bytes_read, padding_size);

            encrypt_block(prev_block, output_buffer, base_round_keys, s_box, number_of_rounds);

            memcpy(ciphertext_buffer + (pos - 16 - bytes_read), output_buffer, 16);
            memcpy(ciphertext_buffer + (pos - bytes_read), temp_ciphertext, bytes_read);

            break;
        }
    }
}

//-----------------------------------AES-END--------------------------------------//

//---------------------------------T-AES-START------------------------------------//
void t_aes_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, uint32_t *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word) {
    
    uint32_t temp_tweaked_keys[60];
    
    uint8_t prev_block[16];
    uint8_t current_block[16];
    uint8_t output_buffer[16];
    size_t bytes_read;
    size_t pos = 0; 

    memcpy(prev_block, plaintext_buffer + pos, 16);
    pos += 16;

    while(1){
        memcpy(temp_tweaked_keys, base_round_keys, 60 * sizeof(uint32_t));
        add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word); 

        size_t remaining = len - pos;
        if (remaining >= 16) {
            bytes_read = 16;
        } else {
            bytes_read = remaining;
        }

        if (bytes_read > 0) {
            memcpy(current_block, plaintext_buffer + pos, bytes_read);
            pos += bytes_read;
        }

        if (bytes_read == 16) { 
            encrypt_block(prev_block, output_buffer, temp_tweaked_keys, s_box, number_of_rounds);
            memcpy(ciphertext_buffer + (pos - 32), output_buffer, 16); 

            memcpy(prev_block, current_block, 16);
            increment_tweak(tweak_key);

        } else if (bytes_read == 0) { 
            encrypt_block(prev_block, output_buffer, temp_tweaked_keys, s_box, number_of_rounds);
            memcpy(ciphertext_buffer + (pos - 16), output_buffer, 16);
            break; 

        } else {
            uint8_t temp_ciphertext[16];
            encrypt_block(prev_block, temp_ciphertext, temp_tweaked_keys, s_box, number_of_rounds);

            int padding_size = 16 - bytes_read;
            memcpy(prev_block, current_block, bytes_read);
            memcpy(prev_block + bytes_read, temp_ciphertext + bytes_read, padding_size);

            increment_tweak(tweak_key);
            memcpy(temp_tweaked_keys, base_round_keys, 60 * sizeof(uint32_t));
            add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word);
            encrypt_block(prev_block, output_buffer, temp_tweaked_keys, s_box, number_of_rounds);
            
            memcpy(ciphertext_buffer + (pos - 16 - bytes_read), output_buffer, 16);
            memcpy(ciphertext_buffer + (pos - bytes_read), temp_ciphertext, bytes_read); 
            break;
        }
    }
}


void t_aes_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len, uint32_t *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word) {
    
    uint32_t temp_tweaked_keys[60];

    uint8_t prev_ciphertext[16];
    uint8_t current_ciphertext[16];
    uint8_t output_plaintext[16];
    size_t bytes_read;
    size_t pos = 0; // Posição de leitura no buffer de entrada

    memcpy(prev_ciphertext, ciphertext_buffer + pos, 16);
    pos += 16;

    while(1) {
        memcpy(temp_tweaked_keys, base_round_keys, 60 * sizeof(uint32_t));
        add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word); // Aplica tweak

        // Lógica de leitura do buffer
        size_t remaining = len - pos;
        if (remaining >= 16) {
            bytes_read = 16;
        } else {
            bytes_read = remaining;
        }

        if (bytes_read > 0) {
            memcpy(current_ciphertext, ciphertext_buffer + pos, bytes_read);
            pos += bytes_read;
        }

        if (bytes_read == 16) {
            decrypt_block(prev_ciphertext, output_plaintext, temp_tweaked_keys, inv_s_box, number_of_rounds);
            memcpy(plaintext_buffer + (pos - 32), output_plaintext, 16); 
            memcpy(prev_ciphertext, current_ciphertext, 16); 
            increment_tweak(tweak_key);

        } else if (bytes_read == 0) {
            decrypt_block(prev_ciphertext, output_plaintext, temp_tweaked_keys, inv_s_box, number_of_rounds);
            memcpy(plaintext_buffer + (pos - 16), output_plaintext, 16);
            break; 

        } else { 
            uint32_t keys_for_Cn_minus_1[60];
            uint8_t next_tweak[16];
            memcpy(next_tweak, tweak_key, 16);
            increment_tweak(next_tweak); 
            memcpy(keys_for_Cn_minus_1, base_round_keys, 60 * sizeof(uint32_t)); 
            add_128_bit(keys_for_Cn_minus_1, next_tweak, rk_start_word);

            uint8_t temp_decrypted_prev[16];
            decrypt_block(prev_ciphertext, temp_decrypted_prev, keys_for_Cn_minus_1, inv_s_box, number_of_rounds);

            uint8_t temp_reconstructed_ciphertext[16]; 
            int padding_size = 16 - bytes_read;
            memcpy(temp_reconstructed_ciphertext, current_ciphertext, bytes_read); 
            memcpy(temp_reconstructed_ciphertext + bytes_read, temp_decrypted_prev + bytes_read, padding_size);

            decrypt_block(temp_reconstructed_ciphertext, output_plaintext, temp_tweaked_keys, inv_s_box, number_of_rounds);

            // Escreve Pn-1
            memcpy(plaintext_buffer + (pos - 16 - bytes_read), output_plaintext, 16);
            // Escreve Pn
            memcpy(plaintext_buffer + (pos - bytes_read), temp_decrypted_prev, bytes_read);

            break;
        }
    }
}

//---------------------------------T-AES-END--------------------------------------//

//---------------------------------T-AES-START-NI---------------------------------//

void t_aes_ni_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, __m128i *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word) {
    
    __m128i temp_tweaked_keys[15];

    uint8_t prev_block[16];
    uint8_t current_block[16];
    uint8_t output_buffer[16];
    size_t bytes_read;
    size_t pos = 0;

    memcpy(prev_block, plaintext_buffer + pos, 16);
    pos += 16;

    while(1){
        memcpy(temp_tweaked_keys, base_round_keys, 15 * sizeof(__m128i));
        add_128_bit_ni(temp_tweaked_keys, tweak_key, rk_start_word);

        size_t remaining = len - pos;
        if (remaining >= 16) {
            bytes_read = 16;
        } else {
            bytes_read = remaining;
        }

        if (bytes_read > 0) {
            memcpy(current_block, plaintext_buffer + pos, bytes_read);
            pos += bytes_read;
        }

        if (bytes_read == 16) {
            encrypt_block_ni(prev_block, output_buffer, temp_tweaked_keys, number_of_rounds);
            memcpy(ciphertext_buffer + (pos - 32), output_buffer, 16); 
            memcpy(prev_block, current_block, 16);
            increment_tweak(tweak_key);

        } else if (bytes_read == 0) {
            encrypt_block_ni(prev_block, output_buffer, temp_tweaked_keys, number_of_rounds);
            memcpy(ciphertext_buffer + (pos - 16), output_buffer, 16);
            break; 

        } else {
            uint8_t temp_ciphertext[16];
            encrypt_block_ni(prev_block, temp_ciphertext, temp_tweaked_keys, number_of_rounds);

            int padding_size = 16 - bytes_read;
            memcpy(prev_block, current_block, bytes_read); 
            memcpy(prev_block + bytes_read, temp_ciphertext + bytes_read, padding_size);

            increment_tweak(tweak_key);
            memcpy(temp_tweaked_keys, base_round_keys, 15 * sizeof(__m128i));
            add_128_bit_ni(temp_tweaked_keys, tweak_key, rk_start_word);

            encrypt_block_ni(prev_block, output_buffer, temp_tweaked_keys, number_of_rounds);
            
            memcpy(ciphertext_buffer + (pos - 16 - bytes_read), output_buffer, 16);
            memcpy(ciphertext_buffer + (pos - bytes_read), temp_ciphertext, bytes_read);
            break;
        }
    }
}

void t_aes_ni_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len,__m128i *base_round_keys, uint8_t *tweak_key, int number_of_rounds, int rk_start_word) {
    
    __m128i temp_tweaked_keys[15];

    uint8_t prev_ciphertext[16];
    uint8_t current_ciphertext[16];
    uint8_t output_plaintext[16];
    size_t bytes_read;
    size_t pos = 0;

    memcpy(prev_ciphertext, ciphertext_buffer + pos, 16);
    pos += 16;

    while(1) {
        memcpy(temp_tweaked_keys, base_round_keys, 15 * sizeof(__m128i));
        add_128_bit_ni(temp_tweaked_keys, tweak_key, rk_start_word);

        size_t remaining = len - pos;
        if (remaining >= 16) {
            bytes_read = 16;
        } else {
            bytes_read = remaining;
        }

        if (bytes_read > 0) {
            memcpy(current_ciphertext, ciphertext_buffer + pos, bytes_read);
            pos += bytes_read;
        }

        if (bytes_read == 16) {
            decrypt_block_ni(prev_ciphertext, output_plaintext, temp_tweaked_keys, number_of_rounds);
            memcpy(plaintext_buffer + (pos - 32), output_plaintext, 16);
            memcpy(prev_ciphertext, current_ciphertext, 16);
            increment_tweak(tweak_key);

        } else if (bytes_read == 0) {
            decrypt_block_ni(prev_ciphertext, output_plaintext, temp_tweaked_keys, number_of_rounds);
            memcpy(plaintext_buffer + (pos - 16), output_plaintext, 16);
            break; 

        } else {
            __m128i keys_for_Cn_minus_1[15]; 
            uint8_t next_tweak[16];
            memcpy(next_tweak, tweak_key, 16);
            increment_tweak(next_tweak); 
            memcpy(keys_for_Cn_minus_1, base_round_keys, 15 * sizeof(__m128i)); 
            add_128_bit_ni(keys_for_Cn_minus_1, next_tweak, rk_start_word);

            uint8_t temp_decrypted_prev[16];
            decrypt_block_ni(prev_ciphertext, temp_decrypted_prev, keys_for_Cn_minus_1, number_of_rounds);

            uint8_t temp_reconstructed_ciphertext[16];
            int padding_size = 16 - bytes_read;
            memcpy(temp_reconstructed_ciphertext, current_ciphertext, bytes_read);
            memcpy(temp_reconstructed_ciphertext + bytes_read, temp_decrypted_prev + bytes_read, padding_size);

            decrypt_block_ni(temp_reconstructed_ciphertext, output_plaintext, temp_tweaked_keys, number_of_rounds);
            
            memcpy(plaintext_buffer + (pos - 16 - bytes_read), output_plaintext, 16);
            memcpy(plaintext_buffer + (pos - bytes_read), temp_decrypted_prev, bytes_read);

            break;
        }
    }
}

//---------------------------------T-AES-END-NI-----------------------------------//

//---------------------------------XTS-START--------------------------------------//

int xts_encrypt_in_mem(const uint8_t *plaintext_buffer, uint8_t *ciphertext_buffer, size_t len, const uint8_t *key, int key_length_bits) {
    EVP_CIPHER_CTX *ctx;
    int len_out = 0;
    const EVP_CIPHER *cipher;

    uint8_t iv[16] = {0}; 

    if (key_length_bits == 128) {
        cipher = EVP_aes_128_xts();
    } else if (key_length_bits == 256) {
        cipher = EVP_aes_256_xts();
    } else {
        fprintf(stderr, "Unsupported key length for XTS: %d\n", key_length_bits);
        return 0;
    }
    
    if (!(ctx = EVP_CIPHER_CTX_new())) return 0;

    if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)) return 0;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext_buffer, &len_out, plaintext_buffer, len)) return 0;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext_buffer + len_out, &len_out)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int xts_decrypt_in_mem(const uint8_t *ciphertext_buffer, uint8_t *plaintext_buffer, size_t len, const uint8_t *key, int key_length_bits) {
    EVP_CIPHER_CTX *ctx;
    int len_out = 0;
    const EVP_CIPHER *cipher;

    uint8_t iv[16] = {0};

    if (key_length_bits == 128) {
        cipher = EVP_aes_128_xts();
    } else if (key_length_bits == 256) {
        cipher = EVP_aes_256_xts();
    } else {
        fprintf(stderr, "Unsupported key length for XTS: %d\n", key_length_bits);
        return 0;
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) return 0;

    if (1 != EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) return 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext_buffer, &len_out, ciphertext_buffer, len)) return 0;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext_buffer + len_out, &len_out)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}


//---------------------------------XTS-END----------------------------------------//