#!/bin/bash


set -e

TEXTO_ORIGINAL="Trabalho de Criptografia Pedro Costa e Henrique Dias 2025"
PASS_MAIN="password123"
PASS_TWEAK="tweak456"

FILE_ORIGINAL="original.bin"
FILE_CIFRADO="temp_cifrado.bin"
FILE_DECIFRADO="temp_decifrado.bin"

# Cores para o output
GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m" 

run_test() {
    TEST_NAME=$1
    shift 
    ARGS=("$@") 

    echo -n "Testando: $TEST_NAME... "

    ./encrypt "${ARGS[@]}" < $FILE_ORIGINAL > $FILE_CIFRADO 2>/dev/null 

    ./decrypt "${ARGS[@]}" < $FILE_CIFRADO > $FILE_DECIFRADO 2>/dev/null

    if diff -q $FILE_ORIGINAL $FILE_DECIFRADO; then
        echo -e "${GREEN}PASSOU${NC}"
    else
        echo -e "${RED}FALHOU${NC}"
        echo "Erro: Ficheiro original e decifrado nao sao identicos para o teste $TEST_NAME"
        exit 1 
    fi
}


echo -n "$TEXTO_ORIGINAL" > $FILE_ORIGINAL
echo "Ficheiro original '$FILE_ORIGINAL' criado."
echo "A iniciar testes (9 combinações)..."

for key_len in 128 192 256; do
    echo "" 
    
    run_test "AES-$key_len (ECB)" "$key_len" "$PASS_MAIN"

    run_test "T-AES-$key_len (SW)" "$key_len" "$PASS_MAIN" "$PASS_TWEAK"

    run_test "T-AES-$key_len (NI)" "$key_len" "$PASS_MAIN" "$PASS_TWEAK" "ni"
done

# 3. Limpeza
echo -e "\n${GREEN}*** SUCESSO! Todos os 9 testes passaram. ***${NC}"
rm $FILE_ORIGINAL $FILE_CIFRADO $FILE_DECIFRADO
echo "Ficheiros temporarios removidos."