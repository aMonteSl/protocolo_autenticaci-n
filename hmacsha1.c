#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define SHA1_BLOCK_SIZE 64 // Tamaño de bloque de SHA-1 en bytes
#define SHA1_DIGEST_SIZE 20 // Tamaño de hash de SHA-1 en bytes

// Función para mostrar un mensaje de advertencia si la clave es demasiado corta
void print_key_length_warning(size_t key_len) {
    if (key_len < SHA1_DIGEST_SIZE) {
        fprintf(stderr, "warning: la clave es demasiado corta (debería ser más larga que %d bytes)\n", SHA1_DIGEST_SIZE);
    }
}

// Función para rellenar la clave con ceros si es menor que el tamaño del bloque de SHA-1
void fill_key_with_zeros(unsigned char *key_buffer, size_t key_len) {
    if (key_len < SHA1_BLOCK_SIZE) {
        memset(key_buffer + key_len, 0, SHA1_BLOCK_SIZE - key_len);
    }
}

// Función para calcular el bloque K XOR ipad o K XOR opad
void xor_with_ipad_or_opad(unsigned char *key_buffer, unsigned char *result, unsigned char xor_value) {
    for (int i = 0; i < SHA1_BLOCK_SIZE; i++) {
        result[i] = key_buffer[i] ^ xor_value;
    }
}

// Función para crear la HMACSHA1 de un fichero usando una clave
void hmacsha1(FILE *data, FILE *key) {
    // Crear el contexto para el hash
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Error al crear el contexto\n");
        exit(EXIT_FAILURE);
    }

    // Inicializar el hash con el algoritmo SHA-1
    if (EVP_DigestInit(ctx, EVP_sha1()) != 1) {
        fprintf(stderr, "Error al inicializar el hash\n");
        exit(EXIT_FAILURE);
    }

    // Leer la clave del fichero y almacenarla en un buffer
    unsigned char key_buffer[SHA1_BLOCK_SIZE];
    size_t key_len = fread(key_buffer, 1, SHA1_BLOCK_SIZE, key);
    if (ferror(key)) {
        fprintf(stderr, "Error al leer la clave\n");
        exit(EXIT_FAILURE);
    }

    // Mostrar advertencia si la clave es demasiado corta
    print_key_length_warning(key_len);

    // Rellenar la clave con ceros si es menor que el tamaño del bloque
    fill_key_with_zeros(key_buffer, key_len);

    // Crear el bloque K XOR ipad
    unsigned char k_ipad[SHA1_BLOCK_SIZE];
    xor_with_ipad_or_opad(key_buffer, k_ipad, 0x36);

    // Actualizar el hash con el bloque K XOR ipad
    if (EVP_DigestUpdate(ctx, k_ipad, SHA1_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error al actualizar el hash con K XOR ipad\n");
        exit(EXIT_FAILURE);
    }

    // Leer el contenido del fichero de datos y actualizar el hash con él
    unsigned char data_buffer[1024];
    size_t data_len;
    while ((data_len = fread(data_buffer, 1, 1024, data)) > 0) {
        if (EVP_DigestUpdate(ctx, data_buffer, data_len) != 1) {
            fprintf(stderr, "Error al actualizar el hash con los datos\n");
            exit(EXIT_FAILURE);
        }
    }
    if (ferror(data)) {
        fprintf(stderr, "Error al leer los datos\n");
        exit(EXIT_FAILURE);
    }

    // Finalizar el hash y obtener el resultado parcial
    unsigned char partial[SHA1_DIGEST_SIZE];
    unsigned int partial_len;
    if (EVP_DigestFinal_ex(ctx, partial, &partial_len) != 1) {
        fprintf(stderr, "Error al finalizar el hash\n");
        exit(EXIT_FAILURE);
    }

    // Reinicializar el hash con el algoritmo SHA-1
    if (EVP_DigestInit(ctx, EVP_sha1()) != 1) {
        fprintf(stderr, "Error al reinicializar el hash\n");
        exit(EXIT_FAILURE);
    }

    // Crear el bloque K XOR opad
    unsigned char k_opad[SHA1_BLOCK_SIZE];
    xor_with_ipad_or_opad(key_buffer, k_opad, 0x5c);

    // Actualizar el hash con el bloque K XOR opad
    if (EVP_DigestUpdate(ctx, k_opad, SHA1_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error al actualizar el hash con K XOR opad\n");
        exit(EXIT_FAILURE);
    }

    // Actualizar el hash con el resultado parcial
    if (EVP_DigestUpdate(ctx, partial, partial_len) != 1) {
        fprintf(stderr, "Error al actualizar el hash con el resultado parcial\n");
        exit(EXIT_FAILURE);
    }

    // Finalizar el hash y obtener el resultado final
    unsigned char final[SHA1_DIGEST_SIZE];
    unsigned int final_len;
    if (EVP_DigestFinal_ex(ctx, final, &final_len) != 1) {
        fprintf(stderr, "Error al finalizar el hash\n");
        exit(EXIT_FAILURE);
    }

    // Liberar el contexto del hash
    EVP_MD_CTX_free(ctx);

    // Escribir el resultado final en hexadecimal por la salida estándar
    for (int i = 0; i < final_len; i++) {
        printf("%02x", final[i]);
    }
    printf("\n");
}

// Función principal del programa
int main(int argc, char *argv[]) {
    // Comprobar el número de argumentos
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <fichero de datos> <fichero de clave>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Abrir el fichero de datos
    FILE *data = fopen(argv[1], "rb");
    if (data == NULL) {
        fprintf(stderr, "Error al abrir el fichero de datos\n");
        exit(EXIT_FAILURE);
    }

    // Abrir el fichero de clave
    FILE *key = fopen(argv[2], "rb");
    if (key == NULL) {
        fprintf(stderr, "Error al abrir el fichero de clave\n");
        exit(EXIT_FAILURE);
    }

    // Llamar a la función para crear la HMACSHA1
    hmacsha1(data, key);

    // Cerrar los ficheros
    fclose(data);
    fclose(key);

    // Terminar el programa
    exit(EXIT_SUCCESS);
}
