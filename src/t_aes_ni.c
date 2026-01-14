#include <stdio.h>
#include <string.h> 
#include <immintrin.h>
#include <wmmintrin.h> 
#include "t_aes_ni.h" 
#include "aes_ni_core.h"
#include "utils.h"

int process_t_aes_ni_encryption(__m128i *base_round_keys, uint8_t *tweak_key,int key_length){
    __m128i temp_tweaked_keys[15];

    int number_of_rounds;
    int rk_start_word; 
    get_t_aes_parameters(key_length, &number_of_rounds, &rk_start_word);

    uint8_t prev_block[16];
    uint8_t current_block[16];
    uint8_t output_buffer[16];
    size_t bytes_read;

    bytes_read = fread(prev_block, 1, 16, stdin);
    if (bytes_read < 16) { 
        return -1;
    }

    while(1){

        memcpy(temp_tweaked_keys, base_round_keys, 15 * sizeof(__m128i));
        add_128_bit_ni(temp_tweaked_keys, tweak_key, rk_start_word);

        bytes_read = fread(current_block, 1, 16, stdin); 

        if (bytes_read == 16) { // Bloco completo
            encrypt_block_ni(prev_block, output_buffer, temp_tweaked_keys, number_of_rounds);
            fwrite(output_buffer, 1, 16, stdout); 
            memcpy(prev_block, current_block, 16);
            increment_tweak(tweak_key); // T -> T+1

        } else if (bytes_read == 0) { // Fim alinhado
            encrypt_block_ni(prev_block, output_buffer, temp_tweaked_keys, number_of_rounds);
            fwrite(output_buffer, 1, 16, stdout);
            break; 

        } else { // fim parcial (Ciphertext Stealing)

            // cifra Pn-1 com tweak T
            uint8_t temp_ciphertext[16];
            encrypt_block_ni(prev_block, temp_ciphertext, temp_tweaked_keys, number_of_rounds);

            // constroi P'n-1
            int padding_size = 16 - bytes_read;
            memcpy(prev_block, current_block, bytes_read); 
            memcpy(prev_block + bytes_read, temp_ciphertext + bytes_read, padding_size);

            // prepara tweak T+1
            increment_tweak(tweak_key);
            memcpy(temp_tweaked_keys, base_round_keys, 15 * sizeof(__m128i));
            add_128_bit_ni(temp_tweaked_keys, tweak_key, rk_start_word); // Aplica T+1

            // cifra P'n-1 com tweak T+1
            encrypt_block_ni(prev_block, output_buffer, temp_tweaked_keys, number_of_rounds);
            
            fwrite(output_buffer, 1, 16, stdout); // Cn-1
            fwrite(temp_ciphertext, 1, bytes_read, stdout); // Cn
            break;
        }
    }
    return 0;
}


int process_t_aes_ni_decryption(__m128i *base_round_keys, uint8_t *tweak_key,int key_length){
    __m128i temp_tweaked_keys[15];

    int number_of_rounds;
    int rk_start_word;
    get_t_aes_parameters(key_length, &number_of_rounds, &rk_start_word);

    uint8_t prev_ciphertext[16];
    uint8_t current_ciphertext[16];
    uint8_t output_plaintext[16];
    size_t bytes_read;

    bytes_read = fread(prev_ciphertext, 1, 16, stdin);
    if (bytes_read < 16) {
        return -1; 
    }

    while(1) {
        memcpy(temp_tweaked_keys, base_round_keys, 15 * sizeof(__m128i));
        add_128_bit_ni(temp_tweaked_keys, tweak_key, rk_start_word);

        bytes_read = fread(current_ciphertext, 1, 16, stdin);

        if (bytes_read == 16) { // bloco completo
            decrypt_block_ni(prev_ciphertext, output_plaintext, temp_tweaked_keys, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout);
            memcpy(prev_ciphertext, current_ciphertext, 16);
            increment_tweak(tweak_key); // T -> T+1

        } else if (bytes_read == 0) { // fim alinhado
            decrypt_block_ni(prev_ciphertext, output_plaintext, temp_tweaked_keys, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout);
            break; 

        } else { // fim parcial (cs inverso)

            // Prepara chaves com T+1
            __m128i keys_for_Cn_minus_1[15]; 
            uint8_t next_tweak[16];
            memcpy(next_tweak, tweak_key, 16);
            increment_tweak(next_tweak); 
            memcpy(keys_for_Cn_minus_1, base_round_keys, 15 * sizeof(__m128i)); 
            add_128_bit_ni(keys_for_Cn_minus_1, next_tweak, rk_start_word); // aplica T+1

            // decifra Cn-1 ('prev_ciphertext') com T+1 -> P'n-1
            uint8_t temp_decrypted_prev[16];
            decrypt_block_ni(prev_ciphertext, temp_decrypted_prev, keys_for_Cn_minus_1, number_of_rounds);

            // constroi C'n-1 = Cn + Padding
            uint8_t temp_reconstructed_ciphertext[16];
            int padding_size = 16 - bytes_read;
            memcpy(temp_reconstructed_ciphertext, current_ciphertext, bytes_read);
            memcpy(temp_reconstructed_ciphertext + bytes_read, temp_decrypted_prev + bytes_read, padding_size);

            decrypt_block_ni(temp_reconstructed_ciphertext, output_plaintext, temp_tweaked_keys, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout); // Escreve Pn-1
            fwrite(temp_decrypted_prev, 1, bytes_read, stdout); // Escreve Pn

            break;
        }
    }
    return 0;
}