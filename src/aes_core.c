#include <string.h>
#include "aes_core.h"

static const uint8_t rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

/*-------------------------HELPER-START---------------------*/
//Recebe uma palavra de 4 bytes  [a0,a1,a2,a3] e devolve [a1,a2,a3,a0].
static uint32_t rot_word(uint32_t word)
{
    uint32_t b0 = (word) & 0x000000FF;
    uint32_t b1 = (word >> 8) & 0x000000FF;
    uint32_t b2 = (word >> 16) & 0x000000FF;
    uint32_t b3 = (word >> 24) & 0x000000FF;

    return (b1) | (b2 << 8) | (b3 << 16) | (b0 << 24);
}

//Faz a subtituicao usando a sbox
static uint32_t sub_word(uint32_t word, const uint8_t *box)
{
    uint32_t b0 = box[(word) & 0x000000FF];
    uint32_t b1 = box[(word >> 8) & 0x000000FF];
    uint32_t b2 = box[(word >> 16) & 0x000000FF];
    uint32_t b3 = box[(word >> 24) & 0x000000FF];

    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

static uint8_t xtime(uint8_t x) {
    //faz o shift para a esquerda (x * 2)
    //verifica se o bit mais alto era 1 (x & 0x80)
    //se era, faz XOR com 0x1B. se não, faz XOR com 0x00
    return (x << 1) ^ ((x & 0x80) ? 0x1B : 0x00);
}

/*--------------------------HELPER-END----------------------*/

static void add_round_key(uint8_t *state, const uint32_t *round_key_words) { 
    const uint8_t *key_bytes = (const uint8_t *)round_key_words; //Apontador para bytes individuais 
    for (int i = 0; i < 16; i++) {
        state[i] = state[i] ^ key_bytes[i];
    }
}
static void mix_columns(uint8_t *state) {
    uint8_t c0, c1, c2, c3; 
    uint8_t t0, t1, t2, t3; 

    for (int i = 0; i < 4; i++) {
        
        c0 = state[i*4 + 0];
        c1 = state[i*4 + 1];
        c2 = state[i*4 + 2];
        c3 = state[i*4 + 3];

        t0 = xtime(c0);
        t1 = xtime(c1);
        t2 = xtime(c2);
        t3 = xtime(c3);

        state[i*4 + 0] = t0 ^ (t1 ^ c1) ^ c2 ^ c3;
        state[i*4 + 1] = c0 ^ t1 ^ (t2 ^ c2) ^ c3;
        state[i*4 + 2] = c0 ^ c1 ^ t2 ^ (t3 ^ c3);
        state[i*4 + 3] = (t0 ^ c0) ^ c1 ^ c2 ^ t3;
    }
}


static void inv_mix_columns(uint8_t *state) {
    uint8_t c0, c1, c2, c3; 
    uint8_t t0, t1, t2, t3, t4, t8; 

    for (int i = 0; i < 4; i++) {
        c0 = state[i*4 + 0];
        c1 = state[i*4 + 1];
        c2 = state[i*4 + 2];
        c3 = state[i*4 + 3];

        t0 = xtime(c0);
        t1 = xtime(c1);
        t2 = xtime(c2);
        t3 = xtime(c3);
        t4 = xtime(t0);
        uint8_t t5 = xtime(t1);
        uint8_t t6 = xtime(t2);
        uint8_t t7 = xtime(t3);
        t8 = xtime(t4);
        uint8_t t9 = xtime(t5);
        uint8_t ta = xtime(t6);
        uint8_t tb = xtime(t7);

        state[i*4 + 0] = (t8 ^ t4 ^ t0) ^ (t9 ^ t1 ^ c1) ^ (ta ^ t6 ^ c2) ^ (tb ^ c3);
        state[i*4 + 1] = (t8 ^ c0) ^ (t9 ^ t5 ^ t1) ^ (ta ^ t2 ^ c2) ^ (tb ^ t7 ^ c3);
        state[i*4 + 2] = (t8 ^ t4 ^ c0) ^ (t9 ^ c1) ^ (ta ^ t6 ^ t2) ^ (tb ^ t3 ^ c3);
        state[i*4 + 3] = (t8 ^ t0 ^ c0) ^ (t9 ^ t5 ^ c1) ^ (ta ^ c2) ^ (tb ^ t7 ^ t3);
    }
}


static void sub_bytes(uint8_t *state,const uint8_t *box) {
    for (int i = 0; i < 16; i++) {
        state[i] = box[state[i]];
    }
}


static void shift_rows(uint8_t *state, int direction) {
    uint8_t temp;

    // --- linha 1 ---
    if (direction == SHIFT_LEFT) {
        // shift 1 para a ESQUERDA: [ 1, 5, 9, 13 ] -> [ 5, 9, 13, 1 ]
        temp = state[1];
        state[1] = state[5];
        state[5] = state[9];
        state[9] = state[13];
        state[13] = temp;
    } else { 
        // shift 1 para a DIREITA: [ 1, 5, 9, 13 ] -> [ 13, 1, 5, 9 ]
        temp = state[13];
        state[13] = state[9];
        state[9] = state[5];
        state[5] = state[1];
        state[1] = temp;
    }

    // --- linha 2 ---
    // shift 2 posições. shift 2 para a esquerda é IGUAL a shift 2 para a direita.
    // [ 2, 6, 10, 14 ] -> [ 10, 14, 2, 6 ]
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // --- linha 3 ---
    if (direction == SHIFT_LEFT) {
        // shift 3 para a ESQUERDA (igual a 1 para a direita): [ 3, 7, 11, 15 ] -> [ 15, 3, 7, 11 ]
        temp = state[15]; 
        state[15] = state[11];
        state[11] = state[7];
        state[7] = state[3];
        state[3] = temp; 
    } else { 
        // shift 3 para a DIREITA (igual a 1 para a esquerda): [ 3, 7, 11, 15 ] -> [ 7, 11, 15, 3 ]
        temp = state[3]; 
        state[3] = state[7];
        state[7] = state[11];
        state[11] = state[15];
        state[15] = temp; 
    }
}

void decrypt_block(const uint8_t *input, uint8_t *output, const uint32_t *round_keys, const uint8_t *inv_box, int number_of_rounds)
{
    uint8_t state[16];
    memcpy(state, input, 16);

    // ultima chave index number_of_rounds * 4
    add_round_key(state, &round_keys[number_of_rounds * 4]);

    for (int round = number_of_rounds - 1; round >= 1; round--) {
        // Ordem inversa: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
        shift_rows(state, SHIFT_RIGHT);
        sub_bytes(state, inv_box);
        add_round_key(state, &round_keys[round * 4]);
        inv_mix_columns(state);
    }

    // ronda final inversa (sem mixcolumns)
    shift_rows(state, SHIFT_RIGHT);
    sub_bytes(state, inv_box);
    add_round_key(state, &round_keys[0]);

    memcpy(output, state, 16);
}

void encrypt_block(const uint8_t *input, uint8_t *output, const uint32_t *round_keys, const uint8_t *box, int number_of_rounds) 
{
    uint8_t state[16];
    memcpy(state, input, 16);

    add_round_key(state, &round_keys[0]);

    for (int round = 1; round < number_of_rounds; round++) {
        sub_bytes(state,box);    
        shift_rows(state, SHIFT_LEFT);   
        mix_columns(state);  
        add_round_key(state, &round_keys[round * 4]);  //&round_keys[round * 4]) endereco de memoria da chave da ronda atual
    }

    // ronda final s/ mix_columns
    sub_bytes(state,box);    
    shift_rows(state, SHIFT_LEFT);   
    add_round_key(state, &round_keys[number_of_rounds * 4]); 

    memcpy(output, state, 16);
}

void key_expansion(const uint8_t *main_key, uint32_t *round_keys, const uint8_t *box, int key_length)
{

    int number_of_rounds;
    int key_size_in_words; //Numero de palavras a que corresponde uma key 

    switch (key_length)
    {
    case 128:
        number_of_rounds = 10;
        key_size_in_words = 4;
        break;
    case 192:
        number_of_rounds = 12;
        key_size_in_words = 6;
        break;
    case 256:
        number_of_rounds = 14;
        key_size_in_words = 8;
        break;
    default:
        return;
    }

    int total_words = 4 * (number_of_rounds + 1);
    memcpy(round_keys, main_key, key_length / 8); //Pomos no nosso round_keys a primeira key que corresponde a nossa main_key, ou seja main_key é a primeira chave de ronda
    
    uint32_t temp;

    for (int i = key_size_in_words; i < total_words; i++) {
        temp = round_keys[i - 1];
        if (i % key_size_in_words == 0) {
            temp = sub_word(rot_word(temp),box);
            temp = temp ^ rcon[i / key_size_in_words];
        }else if (key_size_in_words > 6 && (i % key_size_in_words == 4)) {
            temp = sub_word(temp,box);
        }
        round_keys[i] = round_keys[i - key_size_in_words] ^ temp;
    }
    
}

