#include <stdio.h>
#include <string.h> 
#include "utils.h"  
#include "aes_core.h"


static int count_set_bits(uint8_t n) {
    int count = 0;
    while (n > 0) {
        n &= (n - 1); // Remove o bit '1' menos significativo
        count++;
    }
    return count;
}

static int hamming_distance(const uint8_t *block1, const uint8_t *block2) {
    int distance = 0;
    for (int i = 0; i < 16; i++) {
        // 1 XOR encontra os bits que sao diferentes
        uint8_t diff = block1[i] ^ block2[i];
        // 2 contamos quantos bits '1' (diferencas) existem
        distance += count_set_bits(diff);
    }
    return distance;
}


int main(void) {
    int measures_amount = 100000;
    size_t buffer_size = 16;
    int key_length = 128; 

    uint8_t original_buffer[buffer_size];
    uint8_t output_prev[buffer_size];
    uint8_t output_curr[buffer_size];


    uint8_t main_key[16]; 
    uint8_t tweak_key[16];
    uint32_t base_round_keys[60];
    uint32_t temp_tweaked_keys[60];

    int number_of_rounds;
    int rk_start_word; 
    long long hamming_counts[129] = {0}; 


    generate_random_buffer(original_buffer, buffer_size); 
    
    generate_sha256_hash("my_password_123", 16, main_key);
    generate_sha256_hash("tweal_password_stat", 16, tweak_key);
    
    get_t_aes_parameters(key_length, &number_of_rounds, &rk_start_word);
    key_expansion(main_key, base_round_keys, s_box, key_length);

    memcpy(temp_tweaked_keys, base_round_keys, sizeof(uint32_t) * 60);
    add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word); 
    encrypt_block(original_buffer, output_prev, temp_tweaked_keys, s_box, number_of_rounds);

    fprintf(stderr, "Calculating %d Hamming distances...\n", measures_amount);
    
    for (int i = 0; i < measures_amount; i++) {
        increment_tweak(tweak_key); 

        memcpy(temp_tweaked_keys, base_round_keys, sizeof(uint32_t) * 60); 
        add_128_bit(temp_tweaked_keys, tweak_key, rk_start_word); // aplica T+1
        encrypt_block(original_buffer, output_curr, temp_tweaked_keys, s_box, number_of_rounds);

        int dist = hamming_distance(output_prev, output_curr); 
        hamming_counts[dist]++;

        memcpy(output_prev, output_curr, 16); 
    }

    fprintf(stderr, "Calculation completed. Printing distribution:\n");
    printf("Distance,Count\n"); // CSV format for charts
    for (int i = 0; i < 129; i++) {
        printf("%d,%lld\n", i, hamming_counts[i]);
    }

    
    return 0; 
}