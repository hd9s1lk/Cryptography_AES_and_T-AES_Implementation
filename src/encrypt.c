#include <stdio.h>
#include <stdlib.h> 
#include <string.h> 
#include <immintrin.h>
#include <wmmintrin.h> 
#include "aes_sw.h"
#include "t_aes_sw.h"
#include "t_aes_ni.h"
#include "utils.h"
#include "aes_core.h"
#include "aes_ni_core.h"

int main(int argc, char *argv[]) { 
    if (argc != 3 && argc != 4 && argc !=5) {
        fprintf(stderr, "Invalid number of arguments.\n");
        return 1;
    }

    if (argc == 5) {
        if (strcmp(argv[4], "ni") != 0) {
            fprintf(stderr, "Invalid arg: %s\n", argv[4]); 
            return 1;
        }
    }

    int key_length = atoi(argv[1]); 

    if (key_length != 128 && key_length != 192 && key_length != 256) {
        fprintf(stderr, "Invalid key length. Must be 128, 192, or 256.\n");
        return 1;
    }

    char *password = argv[2];

    size_t key_size_bytes = key_length / 8;
    uint8_t main_key[key_size_bytes];
    generate_sha256_hash(password, key_size_bytes, main_key);

    int operation_success;
    if (argc == 5) {
        fprintf(stderr,"Debug: T-AES NI mode selected with a %d-bit key.\n", key_length);

        char *tweak_password = argv[3];
        uint8_t tweak_key[16];
        __m128i base_round_keys[15]; 

        generate_sha256_hash(tweak_password, 16, tweak_key); 
        key_expansion_ni(main_key, base_round_keys, key_length);
        operation_success = process_t_aes_ni_encryption(base_round_keys, tweak_key, key_length);

    }else if (argc == 4) {
        fprintf(stderr,"Debug: T-AES mode selected with a %d-bit key.\n", key_length);

        char *tweak_password = argv[3];
        uint8_t tweak_key[16];
        uint32_t base_round_keys[60];

        generate_sha256_hash(tweak_password, 16, tweak_key); 
        key_expansion(main_key, base_round_keys, s_box, key_length);
        operation_success = process_t_aes_encryption(base_round_keys, tweak_key, key_length);

    } else {
        fprintf(stderr, "Debug: Standard AES ECB mode selected with a 128-bit key.\n");
        uint32_t base_round_keys[60];
        key_expansion(main_key, base_round_keys, s_box, key_length);
        operation_success = process_aes_encryption(base_round_keys, key_length);
    }

    if(operation_success == -1) {
        fprintf(stderr, "Debug: Binary file to small to encrypt\n");        
    }

    return 0;

}