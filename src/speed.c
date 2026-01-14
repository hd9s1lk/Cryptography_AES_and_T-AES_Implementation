#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
#include <time.h>
#include <immintrin.h>
#include <wmmintrin.h> 
#include "speed_helper.h"
#include "utils.h"
#include "aes_core.h"
#include "aes_ni_core.h"

#define BUFFER_SIZE 4096 // 4KB

//----------------------HELPER-START-------------------------//

static void generate_random_key(char *password, int password_len) {
    const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int num_chars = (int)strlen(chars);
    int i;

    for (i = 0; i < password_len; i++) {
        password[i] = chars[rand() % num_chars];
    }

    password[password_len] = '\0';
}

static void print_results(int measures_amount, long long best_times[4][3], int key_lengths[3]) {
    const char *type_names[] = {"AES-SW", "T-AES-SW", "T-AES-NI", "XTS-AES"};

    printf("\n--- Final Results (Best Time of %d measurements) ---\n", measures_amount);
    printf("Total time (Encryption + Decryption) for 4KB [ns]\n");
    for (int type = 0; type < 4; type++) {
        printf("\n--- Mode: %s ---\n", type_names[type]);

        for (int k_idx = 0; k_idx < 3; k_idx++) {
            if (best_times[type][k_idx] == -1) {
                printf("  Key %d bits: \tN/A\n", key_lengths[k_idx]);
            } else {
                printf("  Key %d bits: \t%lld ns\n",
                       key_lengths[k_idx],     
                       best_times[type][k_idx]); 
            }
        }
    }
}

//----------------------HELPER-END---------------------------//


static long long exec_pipeline(int type, int key_length) {
    int password_len = 32;
    char password[password_len + 1];

    size_t key_size_bytes = key_length / 8;
    uint8_t main_key[key_size_bytes];

    uint8_t original_buffer[BUFFER_SIZE];
    uint8_t cipher_buffer[BUFFER_SIZE];
    uint8_t plain_buffer[BUFFER_SIZE];

    struct timespec start, end;
    long long duration_ns = 0;

    generate_random_buffer(original_buffer, BUFFER_SIZE);

    generate_random_key(password, password_len);
    generate_sha256_hash(password, key_size_bytes, main_key);

    switch (type) {
        case 0: //AES
            {
                uint32_t round_keys[60];
                int number_of_rounds = (key_length == 128) ? 10 : (key_length == 192 ? 12 : 14);
                key_expansion(main_key, round_keys, s_box, key_length);
                clock_gettime(CLOCK_MONOTONIC, &start);
                aes_encrypt_in_mem(original_buffer, cipher_buffer, BUFFER_SIZE, round_keys, number_of_rounds);
                aes_decrypt_in_mem(cipher_buffer, plain_buffer, BUFFER_SIZE, round_keys, number_of_rounds);
                clock_gettime(CLOCK_MONOTONIC, &end);
                duration_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
                return duration_ns;
            }
        case 1: //T-AES
            {
                char tweak_password [password_len + 1];
                uint32_t round_keys[60];
                uint8_t tweak_key[16];
                int number_of_rounds;
                int rk_start_word;
                key_expansion(main_key, round_keys, s_box, key_length);
                generate_random_key(tweak_password, password_len);
                generate_sha256_hash(tweak_password, 16, tweak_key); 
                get_t_aes_parameters(key_length, &number_of_rounds, &rk_start_word);
                clock_gettime(CLOCK_MONOTONIC, &start);
                t_aes_encrypt_in_mem(original_buffer, cipher_buffer, BUFFER_SIZE, round_keys ,tweak_key, number_of_rounds, rk_start_word);
                t_aes_decrypt_in_mem(cipher_buffer, plain_buffer, BUFFER_SIZE, round_keys, tweak_key, number_of_rounds, rk_start_word);
                clock_gettime(CLOCK_MONOTONIC, &end);
                duration_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
                return duration_ns;
            }
        case 2: //T-AES Ni
            {
                char tweak_password [password_len + 1];
                uint8_t tweak_key[16];
                __m128i base_round_keys[15];
                int number_of_rounds;
                int rk_start_word;
                key_expansion_ni(main_key, base_round_keys, key_length);
                generate_random_key(tweak_password, password_len);
                generate_sha256_hash(tweak_password, 16, tweak_key); 
                get_t_aes_parameters(key_length, &number_of_rounds, &rk_start_word);
                clock_gettime(CLOCK_MONOTONIC, &start);
                t_aes_ni_encrypt_in_mem(original_buffer, cipher_buffer, BUFFER_SIZE, base_round_keys, tweak_key, number_of_rounds, rk_start_word);
                t_aes_ni_decrypt_in_mem(cipher_buffer, plain_buffer, BUFFER_SIZE,base_round_keys,tweak_key, number_of_rounds, rk_start_word);
                clock_gettime(CLOCK_MONOTONIC, &end);
                duration_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
                return duration_ns;
            }
        case 3: //XTS
        {
            if (key_length == 192) {
                return -1;
            }
            size_t xts_key_size_bytes = (key_length / 8) * 2;
            uint8_t xts_key[xts_key_size_bytes];
            char password_k1[password_len + 1];
            char password_k2[password_len + 1];
            generate_random_key(password_k1, password_len);
            generate_random_key(password_k2, password_len);

            generate_sha256_hash(password_k1, key_length / 8, xts_key);
            generate_sha256_hash(password_k2, key_length / 8, xts_key + (key_length / 8));

            clock_gettime(CLOCK_MONOTONIC, &start);
            xts_encrypt_in_mem(original_buffer, cipher_buffer, BUFFER_SIZE, xts_key, key_length);
            xts_decrypt_in_mem(cipher_buffer, plain_buffer, BUFFER_SIZE, xts_key, key_length);
            clock_gettime(CLOCK_MONOTONIC, &end);

            duration_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
            return duration_ns;

        }
    }
    return 0;
    
}

int main(void) {
    int measures_amount = 100000; //100000;
    int key_lengths[] = {128, 192, 256};
    long long best_times[4][3]; // [2][2] = T-AES NI, 256
    long long current_time_ns;

    for (int t = 0; t < 4; t++) {
        for (int k = 0; k < 3; k++) {
            best_times[t][k] = -1;
        }
    }


    for(int type = 0; type < 4; type++){
        for (int key_length = 0; key_length < 3; key_length++){
            for(int i = 0; i < measures_amount; i++) {
                current_time_ns = exec_pipeline(type, key_lengths[key_length]);
                if (current_time_ns == -1) continue;
                if (best_times[type][key_length] == -1 || current_time_ns < best_times[type][key_length]) {
                    best_times[type][key_length] = current_time_ns;
                }
            }
        }  
    }

    print_results(measures_amount, best_times, key_lengths);

    return 0;
}