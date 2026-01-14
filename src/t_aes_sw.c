#include <stdio.h>
#include <string.h> 
#include "utils.h"
#include "aes_core.h"
#include "t_aes_sw.h"

int process_t_aes_decryption(uint32_t *base_round_keys, uint8_t *tweak_key,int key_length) {
    uint32_t temp_tweaked_keys[60];

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
        //memcpy(temp_tweaked_keys, base_round_keys, sizeof(base_round_keys));
        memcpy(temp_tweaked_keys, base_round_keys, 60 * sizeof(uint32_t));
        add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word); //aplica tweak

        bytes_read = fread(current_ciphertext, 1, 16, stdin);

        if (bytes_read == 16) { // Bloco completo lido. 'prev_ciphertext' NAO e um dos dois ultimos.
            decrypt_block(prev_ciphertext, output_plaintext, temp_tweaked_keys, inv_s_box, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout); // Escreve o plaintext

            memcpy(prev_ciphertext, current_ciphertext, 16); // Avanca: current -> prev
            increment_tweak(tweak_key); // incrementa tweak

        } else if (bytes_read == 0) { // 'prev_block' é o ultimo.
            decrypt_block(prev_ciphertext, output_plaintext, temp_tweaked_keys, inv_s_box, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout);
            break; 

        } else { //fim, mas bloco parcial. aplicar ciphertext stealing

            uint32_t keys_for_Cn_minus_1[60];
            uint8_t next_tweak[16];
            memcpy(next_tweak, tweak_key, 16);
            increment_tweak(next_tweak); // incrementa next tweak
            //memcpy(keys_for_Cn_minus_1, base_round_keys, sizeof(base_round_keys)); 
            memcpy(keys_for_Cn_minus_1, base_round_keys, 60 * sizeof(uint32_t));
            add_128_bit(keys_for_Cn_minus_1, next_tweak, rk_start_word); // aplica next tweak

            uint8_t temp_decrypted_prev[16]; // P'n-1 = Pn + Padding Roubado
            decrypt_block(prev_ciphertext, temp_decrypted_prev, keys_for_Cn_minus_1, inv_s_box, number_of_rounds);

            uint8_t temp_reconstructed_ciphertext[16]; // C'n-1
            int padding_size = 16 - bytes_read;
            memcpy(temp_reconstructed_ciphertext, current_ciphertext, bytes_read); // copia cn
            memcpy(temp_reconstructed_ciphertext + bytes_read, temp_decrypted_prev + bytes_read, padding_size); // copia padding (do P'n-1 decifrado)

            // decifra C'n-1 usando as chaves com tweak T (guardadas em temp_tweaked_keys) para obter Pn-1
            decrypt_block(temp_reconstructed_ciphertext, output_plaintext, temp_tweaked_keys, inv_s_box, number_of_rounds);

            fwrite(output_plaintext, 1, 16, stdout); //escreve Pn-1
            fwrite(temp_decrypted_prev, 1, bytes_read, stdout); //escreve pn

            break;
        }
    }
    return 0;
   
}

int process_t_aes_encryption(uint32_t *base_round_keys, uint8_t *tweak_key,int key_length){
    
    uint32_t temp_tweaked_keys[60];

    int number_of_rounds;
    int rk_start_word; //onde aplicar tweak

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
        memcpy(temp_tweaked_keys, base_round_keys, 60 * sizeof(uint32_t));
        add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word); // aplica tweak atual 

        bytes_read = fread(current_block, 1, 16, stdin); 

        if (bytes_read == 16) { //lemos um bloco completo. 'prev_block' nao é o ultimo.

            encrypt_block(prev_block, output_buffer, temp_tweaked_keys, s_box, number_of_rounds); //cifrar prev block com chave modificada (teak)
            fwrite(output_buffer, 1, 16, stdout); 

            memcpy(prev_block, current_block, 16); // avança: current -> prev
            increment_tweak(tweak_key);

        } else if (bytes_read == 0) { // 'prev_block' é o ultimo.
            encrypt_block(prev_block, output_buffer, temp_tweaked_keys, s_box, number_of_rounds);
            fwrite(output_buffer, 1, 16, stdout);
            break; 

        } else { //fim, mas bloco parcial. aplicar ciphertext stealing

            //Cifrar penultimo bloco
            uint8_t temp_ciphertext[16];
            encrypt_block(prev_block, temp_ciphertext, temp_tweaked_keys, s_box, number_of_rounds);

            int padding_size = 16 - bytes_read; //calcular quantos bytes roubamos
            memcpy(prev_block, current_block, bytes_read); //copia o bloco parcial  para o início do buffer 'prev_block'
            memcpy(prev_block + bytes_read, temp_ciphertext + bytes_read, padding_size);// copia os bytes roubados (o "padding") para o fim do buffer

            increment_tweak(tweak_key);
            //memcpy(temp_tweaked_keys, base_round_keys, sizeof(base_round_keys)); // recomeca com chaves base
            memcpy(temp_tweaked_keys, base_round_keys, 60 * sizeof(uint32_t));
            add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word); // calcular novo tweak

            encrypt_block(prev_block, output_buffer, temp_tweaked_keys, s_box, number_of_rounds);
            fwrite(output_buffer, 1, 16, stdout);
            fwrite(temp_ciphertext, 1, bytes_read, stdout); //escrever bytes roubados
            break;
        }
    }
    return 0;
   
}