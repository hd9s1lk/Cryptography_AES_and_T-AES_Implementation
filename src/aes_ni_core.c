#include <immintrin.h>
#include <wmmintrin.h>
#include <stdint.h>


#define KEY_EXPAND_128(KEY, TEMP, RCON_CONSTANT) \
    TEMP = _mm_aeskeygenassist_si128(KEY, RCON_CONSTANT); \
    KEY = _mm_xor_si128(KEY, _mm_slli_si128(KEY, 4)); \
    KEY = _mm_xor_si128(KEY, _mm_slli_si128(KEY, 8)); \
    KEY = _mm_xor_si128(KEY, _mm_shuffle_epi32(TEMP, 0xFF)); 


static void key_schedule_128(const uint8_t *key_bytes, __m128i *key_schedule) {
    __m128i k = _mm_loadu_si128((__m128i*)key_bytes);
    __m128i temp; 

    key_schedule[0] = k;

    KEY_EXPAND_128(k, temp, 0x01); key_schedule[1] = k;
    KEY_EXPAND_128(k, temp, 0x02); key_schedule[2] = k;
    KEY_EXPAND_128(k, temp, 0x04); key_schedule[3] = k;
    KEY_EXPAND_128(k, temp, 0x08); key_schedule[4] = k;
    KEY_EXPAND_128(k, temp, 0x10); key_schedule[5] = k;
    KEY_EXPAND_128(k, temp, 0x20); key_schedule[6] = k;
    KEY_EXPAND_128(k, temp, 0x40); key_schedule[7] = k;
    KEY_EXPAND_128(k, temp, 0x80); key_schedule[8] = k;
    KEY_EXPAND_128(k, temp, 0x1B); key_schedule[9] = k;
    KEY_EXPAND_128(k, temp, 0x36); key_schedule[10] = k;
}

// VERSÃO CORRIGIDA E SEGURA para AES-192 (não usa _mm_shuffle_epi64)
static void key_schedule_192(const uint8_t* key_bytes, __m128i* key_schedule) {
    __m128i temp1, temp2;
    __m128i k0, k1_lo, k1_hi;

    // Carregamento seguro: 16 bytes para k0, 8 bytes para k1_lo
    k0 = _mm_loadu_si128((const __m128i*)key_bytes);
    k1_lo = _mm_loadl_epi64((const __m128i*)(key_bytes + 16));
    
    key_schedule[0] = k0;
    
    // Iteração 1
    temp1 = _mm_aeskeygenassist_si128(k1_lo, 0x01);
    temp2 = _mm_shuffle_epi32(temp1, 0x55);
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 4));
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 8));
    k0 = _mm_xor_si128(k0, temp2);
    
    k1_hi = _mm_shuffle_epi32(k0, 0xFF);
    k1_lo = _mm_xor_si128(k1_lo, _mm_slli_si128(k1_lo, 4));
    k1_lo = _mm_xor_si128(k1_lo, k1_hi);
    
    key_schedule[1] = _mm_castpd_si128(_mm_unpacklo_pd(_mm_castsi128_pd(k1_lo), _mm_castsi128_pd(k0)));
    key_schedule[2] = _mm_castpd_si128(_mm_unpackhi_pd(_mm_castsi128_pd(k0), _mm_castsi128_pd(k1_lo)));

    // Iteração 2
    temp1 = _mm_aeskeygenassist_si128(k1_lo, 0x02);
    temp2 = _mm_shuffle_epi32(temp1, 0x55);
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 4));
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 8));
    k0 = _mm_xor_si128(k0, temp2);
    key_schedule[3] = k0;

    k1_hi = _mm_shuffle_epi32(k0, 0xFF);
    k1_lo = _mm_xor_si128(k1_lo, _mm_slli_si128(k1_lo, 4));
    k1_lo = _mm_xor_si128(k1_lo, k1_hi);
    
    key_schedule[4] = _mm_castpd_si128(_mm_unpacklo_pd(_mm_castsi128_pd(k1_lo), _mm_castsi128_pd(k0)));
    key_schedule[5] = _mm_castpd_si128(_mm_unpackhi_pd(_mm_castsi128_pd(k0), _mm_castsi128_pd(k1_lo)));

    // Iteração 3
    temp1 = _mm_aeskeygenassist_si128(k1_lo, 0x04);
    temp2 = _mm_shuffle_epi32(temp1, 0x55);
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 4));
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 8));
    k0 = _mm_xor_si128(k0, temp2);
    key_schedule[6] = k0;

    k1_hi = _mm_shuffle_epi32(k0, 0xFF);
    k1_lo = _mm_xor_si128(k1_lo, _mm_slli_si128(k1_lo, 4));
    k1_lo = _mm_xor_si128(k1_lo, k1_hi);

    key_schedule[7] = _mm_castpd_si128(_mm_unpacklo_pd(_mm_castsi128_pd(k1_lo), _mm_castsi128_pd(k0)));
    key_schedule[8] = _mm_castpd_si128(_mm_unpackhi_pd(_mm_castsi128_pd(k0), _mm_castsi128_pd(k1_lo)));

    // Iteração 4
    temp1 = _mm_aeskeygenassist_si128(k1_lo, 0x08);
    temp2 = _mm_shuffle_epi32(temp1, 0x55);
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 4));
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 8));
    k0 = _mm_xor_si128(k0, temp2);
    key_schedule[9] = k0;

    k1_hi = _mm_shuffle_epi32(k0, 0xFF);
    k1_lo = _mm_xor_si128(k1_lo, _mm_slli_si128(k1_lo, 4));
    k1_lo = _mm_xor_si128(k1_lo, k1_hi);

    key_schedule[10] = _mm_castpd_si128(_mm_unpacklo_pd(_mm_castsi128_pd(k1_lo), _mm_castsi128_pd(k0)));
    key_schedule[11] = _mm_castpd_si128(_mm_unpackhi_pd(_mm_castsi128_pd(k0), _mm_castsi128_pd(k1_lo)));

    // Iteração final para a última chave de ronda
    temp1 = _mm_aeskeygenassist_si128(k1_lo, 0x10);
    temp2 = _mm_shuffle_epi32(temp1, 0x55);
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 4));
    k0 = _mm_xor_si128(k0, _mm_slli_si128(k0, 8));
    k0 = _mm_xor_si128(k0, temp2);
    key_schedule[12] = k0;
}


// VERSÃO CORRIGIDA para AES-256
static void key_schedule_256(const uint8_t *key_bytes, __m128i *key_schedule) {
    __m128i k0, k1, temp;
    
    k0 = _mm_loadu_si128((__m128i*)key_bytes);
    k1 = _mm_loadu_si128((__m128i*)(key_bytes + 16));

    key_schedule[0] = k0;
    key_schedule[1] = k1;

    // 1ª iteração 
    KEY_EXPAND_128(k0, temp, 0x01); 
    key_schedule[2] = k0;
    temp = _mm_aeskeygenassist_si128(k0, 0x00);
    temp = _mm_shuffle_epi32(temp, 0xAA);
    k1 = _mm_xor_si128(k1, temp); // CORREÇÃO: Removidos os shifts incorretos
    key_schedule[3] = k1;

    // 2ª iteração 
    KEY_EXPAND_128(k0, temp, 0x02); 
    key_schedule[4] = k0;
    temp = _mm_aeskeygenassist_si128(k0, 0x00);
    temp = _mm_shuffle_epi32(temp, 0xAA);
    k1 = _mm_xor_si128(k1, temp); // CORREÇÃO
    key_schedule[5] = k1;

    // 3ª iteração 
    KEY_EXPAND_128(k0, temp, 0x04); 
    key_schedule[6] = k0;
    temp = _mm_aeskeygenassist_si128(k0, 0x00);
    temp = _mm_shuffle_epi32(temp, 0xAA);
    k1 = _mm_xor_si128(k1, temp); // CORREÇÃO
    key_schedule[7] = k1;

    // 4ª iteração 
    KEY_EXPAND_128(k0, temp, 0x08); 
    key_schedule[8] = k0;
    temp = _mm_aeskeygenassist_si128(k0, 0x00);
    temp = _mm_shuffle_epi32(temp, 0xAA);
    k1 = _mm_xor_si128(k1, temp); // CORREÇÃO
    key_schedule[9] = k1;

    // 5ª iteração 
    KEY_EXPAND_128(k0, temp, 0x10); 
    key_schedule[10] = k0;
    temp = _mm_aeskeygenassist_si128(k0, 0x00);
    temp = _mm_shuffle_epi32(temp, 0xAA);
    k1 = _mm_xor_si128(k1, temp); // CORREÇÃO
    key_schedule[11] = k1;

    // 6ª iteração 
    KEY_EXPAND_128(k0, temp, 0x20); 
    key_schedule[12] = k0;
    temp = _mm_aeskeygenassist_si128(k0, 0x00);
    temp = _mm_shuffle_epi32(temp, 0xAA);
    k1 = _mm_xor_si128(k1, temp); // CORREÇÃO
    key_schedule[13] = k1;

    // 7ª iteração 
    KEY_EXPAND_128(k0, temp, 0x40); 
    key_schedule[14] = k0;
}


void key_expansion_ni(const uint8_t *key_bytes, __m128i *key_schedule, int key_length) {
    if (key_length == 128) {
        key_schedule_128(key_bytes, key_schedule);
    } else if (key_length == 192) {
        key_schedule_192(key_bytes, key_schedule);
    } else if (key_length == 256) {
        key_schedule_256(key_bytes, key_schedule);
    }
}

void encrypt_block_ni(const uint8_t *input, uint8_t *output, const __m128i *key_schedule, int num_rounds) {
    __m128i block = _mm_loadu_si128((__m128i*)input);
    block = _mm_xor_si128(block, key_schedule[0]);
    for (int i = 1; i < num_rounds; i++) {
        block = _mm_aesenc_si128(block, key_schedule[i]);
    }
    block = _mm_aesenclast_si128(block, key_schedule[num_rounds]);
    _mm_storeu_si128((__m128i*)output, block);
}

void decrypt_block_ni(const uint8_t *input, uint8_t *output, const __m128i *key_schedule, int num_rounds) {
    __m128i block = _mm_loadu_si128((__m128i*)input);
    __m128i key_temp;

    block = _mm_xor_si128(block, key_schedule[num_rounds]);

    for (int i = num_rounds - 1; i > 0; i--) {
        key_temp = _mm_aesimc_si128(key_schedule[i]);
        block = _mm_aesdec_si128(block, key_temp);
    }
    
    block = _mm_aesdeclast_si128(block, key_schedule[0]);
    _mm_storeu_si128((__m128i*)output, block);
}