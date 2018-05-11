#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

/*********************/
/* Función principal */
/*********************/

int main(int argc, char *argv[]) {
    ProcesaArgv(argc, argv);
    datos = leeDatos(ent);
    cifraODescifra(datos);
    return 0;
}


/******************************************************************************/
/* Funciones de apoyo: Funciones simples que permiten evitar la ofuscación de */
/*   código y que permiten facilitar la lectura del código                    */
/******************************************************************************/

/*
 * Transforma los bits a, b, c, d en el entero 0xabcd.
 */
word toWord(byte a, byte b, byte c, byte d) {
    return (a & 0xff) << 24 | (b & 0x00ff) << 16 | (c & 0x0000ff) << 8 | d;
}

/*
 *
 */
byte xtime(byte a) {
    return (a << 1 ^ ((a & 0x80) ? 0x1b : 0)) & 0xff;
}

byte xtime9(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i;
}

byte xtime11(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i2 ^ i;
}

byte xtime13(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i4 ^ i;
}

byte xtime14(byte i) {
    byte i2 = xtime(i), i4 = xtime(i2), i8 = xtime(i4);
    return i8 ^ i4 ^ i2;
}

word subWord(word w) {
    word result = 0;
    for (int i = 0; i < 4; i++) result ^= sbox[(w >> (3 - i) * 8) & 0x000000ff] << (3 - i) * 8;
    return result;
}

word rotWord(word w) {
    return (w << 8 | w >> 24) & 0xffffffff;
}

void copySubArray(word* in, word* out, int i, int j) {
    for (int k = 0 ; i < j; i++, k++) out[k] = in[i];
}

void copySubArrayByte(byte* in, byte* out, int i, int j) {
    for (int k = 0 ; i < j; i++, k++) out[k] = in[i];
}

void subBytes(byte* state) {
    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
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
    for (int i = 0; i < 16; i += 4) {
        byte s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
        state[i] = xtime(s0) ^ (s1 ^ xtime(s1)) ^ s2 ^ s3;
        state[i + 1] = s0 ^ xtime(s1) ^ (s2 ^ xtime(s2)) ^ s3;
        state[i + 2] = s0 ^ s1 ^ xtime(s2) ^ (s3 ^ xtime(s3));
        state[i + 3] = (s0 ^ xtime(s0)) ^ s1 ^ s2 ^ xtime(s3);
    }
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

/****************************************/
/* Sección de funciones para descifrado */
/****************************************/


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

void invMixColumns(byte* state) {
    int i;
    for (i = 0; i < 16; i += 4) {
        byte s0 = state[i], s1 = state[i + 1], s2 = state[i + 2], s3 = state[i + 3];
        state[i] = xtime14(s0) ^ xtime11(s1) ^ xtime13(s2) ^ xtime9(s3);
        state[i + 1] = xtime9(s0) ^ xtime14(s1) ^ xtime11(s2) ^ xtime13(s3);
        state[i + 2] = xtime13(s0) ^ xtime9(s1) ^ xtime14(s2) ^ xtime11(s3);
        state[i + 3] = xtime11(s0) ^ xtime13(s1) ^ xtime9(s2) ^ xtime14(s3);
    }
}

void invCipher(byte* in, byte* out, word* w) {
    byte* state = (byte*) malloc(4*Nb*sizeof(byte));
    word* aux = (word *) calloc(Nb,  sizeof(word));

    memcpy(state, in, 16);

    copySubArray(w, aux, Nr*Nb, (Nr + 1) * Nb);
    addRoundKey(state, aux);

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

void substring(char s[], char sub[], int p, int l) {
   int c = 0;
    while (c < l) {
      sub[c] = s[p+c-1];
      c++;
   }
   sub[c] = '\0';
}

void cifra(byte* input, byte* output, word* expandedKeys, int longEnt, int* longSal) {
    int longPad = 16 - (longEnt % 16);
    byte* state = (byte*) calloc(4 *Nb, sizeof(byte));
    byte* out = (byte*) calloc(4 * Nb, sizeof(byte));
    for(int i=0; i < longPad; i++) {
        input[longEnt + i] = (unsigned int)longPad;
    }
    *longSal = longEnt + longPad;  /* La longitud del buffer por cifrar. */
    /* ¡A cifrar! */
    for(int i=0; i < *longSal; i+=16) {
        copySubArrayByte(input, state, i, i + 16);
        cipher(state, out, expandedKeys);
        for (int j = 0; j < 16; j++) {
            output[i+j] = out[j];
        }
    }
}

void descifra(byte* input, byte* output, word* expandedKeys, int longEnt,int *longSal) {
    byte* state = (byte*) calloc(4 * Nb, sizeof(byte));
    byte* out = (byte*) calloc(4 * Nb, sizeof(byte));
    /* ¡A descifrar! */
    for (int i = 0; i < longEnt; i += 16) {
        copySubArrayByte(input, state, i, i + 16);
        invCipher(state, out, expandedKeys);
        for (int j = 0; j < 16; j++) {
            output[i+j] = out[j];
        }
    }
    *longSal = longEnt - (byte) output[longEnt - 1];  /* Quitamos padding. */
}

void cifraODescifra(byte* datos) {
    int* longSal = malloc(sizeof(int));
    FILE* salida;
    byte* output = (byte*) calloc(tamArchivo, sizeof(byte));
    word* w = (word*) calloc(Nb * (Nr + 1), sizeof(word));
    keyExpansion(llave, w, Nk);
    if (cifrar) {
        cifra(datos, output, w, tamArchivo, longSal);
    } else {
        descifra(datos, output, w, tamArchivo, longSal);
    }
    salida = fopen(sal, "wb");
    fwrite(output, 1, *longSal, salida);
    fclose(salida);
    free(datos);
}

byte* leeDatos(char* nombre) {
    FILE *archivo;
    int pad;
    byte* datos;
    archivo = fopen(nombre, "rb");
    if (!archivo) {
        fprintf(stderr, "No se puede abrir el archivo %s\n", nombre);
        exit(1);
    }
    fseek(archivo, 0, SEEK_END);
    tamArchivo = ftell(archivo);
    pad = 16 - (tamArchivo % 16);
    fseek(archivo, 0, SEEK_SET);
    datos = malloc(tamArchivo + pad);
    if (!datos) {
        fprintf(stderr, "Error de memoria!");
        fclose(archivo);
        exit(1);
    }
    fread(datos, tamArchivo, 1, archivo);
    fclose(archivo);
    return datos;
}

/**
 * Procesa los argumentos que se la pasan al programa.
 */
void ProcesaArgv(int argc, char *argv[]) {
    if (argc < 2)  {
        uso();
        exit(0);
    }

    strcpy(ent, argv[4]);
    strcpy(sal, argv[4]);
    strcpy(archivoLlave, argv[3]);
    char type[3];
    substring(argv[2], type, 2, 4);
    if (argv[2][0] == '-') {
        if (!strcmp("128", type)) {
            tipo = 128, Nk = 4, Nr = 10;
        } else if (!strcmp("192", type)) {
            tipo = 192, Nk = 6, Nr = 12;
        } else if (!strcmp("256", type)) {
            tipo = 256, Nk = 8, Nk = 14;
        } else {
            uso();
            exit(0);
        }
    }


    if (argv[1][0] == '-') {
        switch (argv[1][1]) {
        case 'c':
            cifrar = TRUE;
            break;
        case 'd':
            cifrar = FALSE;
            break;
        case 'h':
        default:
            uso();
            exit(0);
        }
    }

    if ((fpllave = fopen(archivoLlave, "r")) == NULL) {
        fprintf(stderr, "RC2-Error: No puedo abrir la llave %s\n", archivoLlave);
        exit(1);
    } else {
        int i;
        char* text = malloc(sizeof(char) * 2);
        llave = (byte*) calloc(4 * Nk, sizeof(byte));
        for(i = 0; i < 4 * Nk; i++) {
            fread(&text[0], 1, 1, fpllave);
            if (text[0] == ' ') {
                fread(&text[0], 1, 1, fpllave);
            }
            fread(&text[1], 1, 1, fpllave);
            llave[i] = (unsigned char) strtol(text, NULL, 16);
        }
        free(text);
    }
}


void uso() {
    printf("\nUso: $ aes [- c | -d ] [-128 | -192 | -256] LLAVE  ARCHIVO\n");
    printf("Herramienta para cifrar usando el algoritmo AES. LLAVE y ARCHIVO son archivos.\n");
    printf("Se espera que el formato de la llave se encuentre en hexadecimal de tamaño 128, 192 ó 256.\n");
    printf("\nLas opciones disponibles de uso son las siguientes:\n");
    printf("       -c: para cifrar el archivo.\n");
    printf("       -d: para descifrar el archivo.\n");
    printf("\n\nEjemplo de uso: RC2 -c key 5 64 datos.txt\n\n");
    printf("Donde \"key\" es el archivo con la llave, 5 es el número de bytes de la llave y\n");
    printf("64 es la longitud máxima efectiva de la llave. \"datos.txt\" es el archivo\n");
    printf("a cifrar\n");
}
