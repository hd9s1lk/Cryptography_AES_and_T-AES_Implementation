#include <stdio.h>
#include <string.h>
#include "utils.h"
#include "aes_core.h"
#include "aes_sw.h"

static int get_number_of_rounds(int key_length) {
    switch (key_length) {
        case 128: return 10; 
        case 192: return 12;
        case 256: return 14;
    }
    return 0;
}

int process_aes_decryption(uint32_t *base_round_keys, int key_length) {
    int number_of_rounds = get_number_of_rounds(key_length);

    uint8_t prev_ciphertext[16];
    uint8_t current_ciphertext[16];
    uint8_t output_plaintext[16];
    size_t bytes_read;

    bytes_read = fread(prev_ciphertext, 1, 16, stdin);
    if (bytes_read < 16) { 
        return -1;
    }

    while(1) {
        bytes_read = fread(current_ciphertext, 1, 16, stdin);

        if (bytes_read == 16) { // bloco completo. 'prev_ciphertext' NÃO é um dos dois ultimos.

            decrypt_block(prev_ciphertext, output_plaintext, base_round_keys, inv_s_box, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout);
            memcpy(prev_ciphertext, current_ciphertext, 16);

        } else if (bytes_read == 0) { // 'prev_ciphertext' era o último bloco (tamanho alinhado).

            decrypt_block(prev_ciphertext, output_plaintext, base_round_keys, inv_s_box, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout);
            break; 

        } else { //'prev_ciphertext' é Cn-1, 'current_ciphertext' é Cn (parcial, com 'bytes_read').

            // decifrar o penultimo bloco (Cn-1, em 'prev_ciphertext') para obter Pn-1
            uint8_t temp_decrypted_prev[16]; // P'n-1 = Pn + Padding Roubado
            decrypt_block(prev_ciphertext, temp_decrypted_prev, base_round_keys, inv_s_box, number_of_rounds);

            // reconstruir C'n-1 para obter Pn-1
            uint8_t temp_reconstructed_ciphertext[16]; // C'n-1
            int padding_size = 16 - bytes_read;
            memcpy(temp_reconstructed_ciphertext, current_ciphertext, bytes_read); // Copia Cn para o início
            memcpy(temp_reconstructed_ciphertext + bytes_read, temp_decrypted_prev + bytes_read, padding_size); // Copia Padding para o fim

            decrypt_block(temp_reconstructed_ciphertext, output_plaintext, base_round_keys, inv_s_box, number_of_rounds);
            fwrite(output_plaintext, 1, 16, stdout); //escreve Pn-1
            fwrite(temp_decrypted_prev, 1, bytes_read, stdout); // Escreve Pn


            break;
        }
    }
    return 0;

}

int process_aes_encryption(uint32_t *base_round_keys, int key_length) {
    int number_of_rounds = get_number_of_rounds(key_length);

    //generate_sha256_hash(password,key_size_bytes,main_key);
    //key_expansion(main_key, round_keys, s_box, key_length);
    
    uint8_t prev_block[16];
    uint8_t current_block[16];
    uint8_t output_buffer[16];
    size_t bytes_read;

    bytes_read = fread(prev_block, 1, 16, stdin);

    if (bytes_read < 16) { //ficheiro menos q um bloco
        return -1; 
    }

    while(1){
        bytes_read = fread(current_block, 1, 16, stdin); 
        if (bytes_read == 16) { // lemos um bloco completo. p 'prev_block' nao é o ultimo.
            encrypt_block(prev_block, output_buffer, base_round_keys, s_box, number_of_rounds);
            fwrite(output_buffer, 1, 16, stdout);
            memcpy(prev_block, current_block, 16); //current block passa a ser prev block

        }else if (bytes_read == 0) { //Fim. O prev block era o ultimo bloco (input tamanho perfeito)
            encrypt_block(prev_block, output_buffer, base_round_keys, s_box, number_of_rounds);
            fwrite(output_buffer, 1, 16, stdout);
            break;
        }else { //fim, mas bloco parcial. aplicar ciphertext stealing
            //Ex: prev_block="ABCDEFGHIJKLMnop", current_block="qrst", bytes_read=4
            
            //Cifrar penultimo bloco (Pn-1)
            uint8_t temp_ciphertext[16]; // C'n-1 temporario
            encrypt_block(prev_block, temp_ciphertext, base_round_keys, s_box, number_of_rounds);
            // Ex: temp_ciphertext = "112233445566778899aabbccddeeff"

            // Constroi P'n-1 = Pn + Padding Roubado
            int padding_size = 16 - bytes_read; // calcular quantos bytes faltam
            // Ex: padding_size = 12
            memcpy(prev_block, current_block, bytes_read); // copia bloco parcial (Pn) para inicio de prev_block
            // Ex: prev_block = [ "qrst" | lixo ... ]
            memcpy(prev_block + bytes_read, temp_ciphertext + bytes_read, padding_size); // copia fim roubado ("padding") de C'n-1 para fim de prev_block
            // Ex: prev_block = "qrst5566778899aabbccddeeff" (P'n-1 completo)

            // Cifra P'n-1 para obter Cn-1 final
            encrypt_block(prev_block, output_buffer, base_round_keys, s_box, number_of_rounds);
            // Ex: output_buffer = "ZYXWVUTSRQPONMLKJ" (Cn-1 final)

            fwrite(output_buffer, 1, 16, stdout);
            // Ex: Escreve "ZYXWVUTSRQPONMLKJ" (cn-1)

            fwrite(temp_ciphertext, 1, bytes_read, stdout);
            // Ex: Escreve "11223344" (Cn)

            break;
        }
    }
    return 0;

}