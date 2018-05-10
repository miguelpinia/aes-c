#include <string.h>
#include <stdlib.h>
#include "aes.h"

void subBytes(byte* state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
}

word toWord(byte a, byte b, byte c, byte d) {
    return (a & 0xff) << 24 | (b & 0x00ff) << 16 | (c & 0x0000ff) << 8 | d;
}

byte xtime(byte a) {
    return (a << 1 ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}

void shiftRows(byte* state) {
    byte* s = (byte*) malloc(16 * sizeof(byte));
    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            s[c * 4 + r] = state[((c * 4 + r) + (4 * r)) % 16];
        }
        for (int c = 0; c < Nb; c++) {
            state[c * 4 + r] = s[c * 4 + r];
        }
    }
    free(s);
}

void mixColumns(byte* state) {
    int i;
    for (i = 0; i < 16; i += 4) {
        byte s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
        state[i] = xtime(s0) ^ (s1 ^ xtime(s1)) ^ s2 ^ s3;
        state[i + 1] = s0 ^ xtime(s1) ^ (s2 ^ xtime(s2)) ^ s3;
        state[i + 2] = s0 ^ s1 ^ xtime(s2) ^ (s3 ^ xtime(s3));
        state[i + 3] = (s0 ^ xtime(s0)) ^ s1 ^ s2 ^ xtime(s3);
    }
}

word subWord(word w) {
    word result = 0;
    int i;
    for (i = 0; i < 4; i++) result ^= sbox[(w >> (3 - i) * 8) & 0x000000ff] << (3 - i) * 8;
    return result;
}

word rotWord(word w) {
    return (w<<8|w>>24) & 0xffffffff;
}

void keyExpansion(byte* key, word* w, int nk) {
    word temp;
    int i = 0;
    while (i < nk) {
        w[i] = toWord(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
        i += 1;
    }
    i = nk;
    while (i < Nb * (Nr + 1)) {
        temp = w[i - 1];
        if (i % nk == 0)                temp = subWord(rotWord(temp)) ^ rcon[i / nk];
        else if (nk > 6 && i % nk == 4) temp = subWord(temp);
        w[i] = w[i - nk] ^ temp;
        i = i + 1;
    }
}

void addRoundKey(byte* state, word* key) {
    for (int i = 0; i < 4; i++) {
        state[i * 4] ^= key[i] >> 24 & 0x000000ff;
        state[(i * 4) + 1] ^= key[i] >> 16 & 0x000000ff;
        state[(i * 4) + 2] ^= key[i] >> 8 & 0x000000ff;
        state[(i * 4) + 3] ^= key[i] & 0x000000ff;
    }
}

void copySubArray(word* in, word* out, int i, int j) {
    for (int k = 0 ; i < j; i++, k++) {
        out[k] = in[i];
    }
}

void cipher(byte* in, byte* out, word* w) {
    byte* state = (byte*) malloc(4*Nb*sizeof(byte));
    word* aux = (word *) calloc(Nb,  sizeof(word));

    memcpy(state, in, 16);
    copySubArray(w, aux, 0, Nb);
    addRoundKey(state, aux);

    for (int i = 1; i < Nr; i++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        copySubArray(w, aux, i * Nb, (i + 1) * Nb);
        addRoundKey(state, aux);
    }

    subBytes(state);
    shiftRows(state);
    copySubArray(w, aux, Nr * Nb, (Nr + 1) * Nb);
    addRoundKey(state, aux);
    memcpy(out, state, 16);
    free(aux);
    free(state);
}

void invShiftRows(byte* state) {
    byte* s = (byte*) malloc(16 * sizeof(byte));
    for (int r = 1; r < 4; r++) {
        for (int c = 0; c < Nb; c++) {
            s[((c * 4 + r) + 4*r) % 16] = state[c * 4 + r];
        }
        for (int c = 0; c < Nb; c++) {
            state[c * 4 + r] = s[c * 4 + r];
        }
    }
    free(s);
}

void invSubBytes(byte* state) {
    for (int i = 0; i < 16; i++) state[i] = inv_sbox[state[i]];
}

byte s9(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i;
}

byte s11(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i2 ^ i;
}

byte s13(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i4 ^ i;
}

byte s14(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i4 ^ i2;
}

void invMixColumns(byte* state) {
    int i;
    for (i = 0; i < 16; i += 4) {
        byte s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
        state[i] = s14(s0) ^ s11(s1) ^ s13(s2) ^ s9(s3);
        state[i + 1] = s9(s0) ^ s14(s1) ^ s11(s2) ^ s13(s3);
        state[i + 2] = s13(s0) ^ s9(s1) ^ s14(s2) ^ s11(s3);
        state[i + 3] = s11(s0) ^ s13(s1) ^ s9(s2) ^ s14(s3);
    }
}



void invCipher(byte* in, byte* out, word* w) {
    byte* state = (byte*) malloc(4*Nb*sizeof(byte));
    word* aux = (word *) calloc(Nb,  sizeof(word));

    memcpy(state, in, 16);

    copySubArray(w, aux, Nr*Nb, (Nr + 1) * Nb);
    addRoundKey(state, aux);
    imprimeEstado(state);

    for (int i = Nr - 1; i > 0; i--) {
        invShiftRows(state);
        invSubBytes(state);
        copySubArray(w, aux, i*Nb, (i + 1) * Nb);
        addRoundKey(state, aux);
        invMixColumns(state);
    }

    invShiftRows(state);
    invSubBytes(state);
    copySubArray(w, aux, 0, Nb);
    addRoundKey(state, aux);
    memcpy(out, state, 16);
    free(aux);
    free(state);
}

void imprimeEstado(byte* state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x ", state[j * 4 + i]);
        }
        printf("\n");
    }
}

int main() {
    byte key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte nkey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    word* w = (word*) calloc(Nb * (Nr + 1), sizeof(word));
    word* w2 = (word*) calloc(Nb * (Nr + 1), sizeof(word));
    byte* out = (byte *) calloc(16, sizeof(byte));
    byte* out2 = (byte *) calloc(16, sizeof(byte));
    byte input[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    byte inputInv[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
    keyExpansion(key, w, Nk);

    printf("Cipher\n\n");
    printf("Estado: \n");
    imprimeEstado(input);
    cipher(input, out, w);
    printf("\nCifrado\n");
    imprimeEstado(out);
    keyExpansion(nkey, w2, Nk);
    printf("\n\nEstado\n\n");
    invCipher(inputInv, out2, w2);
    printf("\nDescifrado\n");
    imprimeEstado(out2);
    free(out);
    free(out2);
    free(w);
    free(w2);
    return 0;
}
