#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h> // Include the necessary header file
#include <netinet/in.h>
#include <unistd.h>
#include <string.h> // Para memcmp
#include <openssl/hmac.h> // Para HMAC
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/sha.h>
#include <time.h> // Para time
#include <stdbool.h> // Para bool


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

// Función para crear la HMACSHA1 de unos datos y una clave
void hmacsha1(unsigned char *key, int key_length, unsigned char *data, unsigned int data_length, unsigned char *hmac){

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

    // Usar la clave directamente en lugar de leerla de un archivo
    unsigned char key_buffer[SHA1_BLOCK_SIZE];
    memcpy(key_buffer, key, key_length);

    // Mostrar advertencia si la clave es demasiado corta
    print_key_length_warning(key_length);

    // Rellenar la clave con ceros si es menor que el tamaño del bloque
    fill_key_with_zeros(key_buffer, key_length);

    // Crear el bloque K XOR ipad
    unsigned char k_ipad[SHA1_BLOCK_SIZE];
    xor_with_ipad_or_opad(key_buffer, k_ipad, 0x36);

    // Actualizar el hash con el bloque K XOR ipad
    if (EVP_DigestUpdate(ctx, k_ipad, SHA1_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error al actualizar el hash con K XOR ipad\n");
        exit(EXIT_FAILURE);
    }

    // Usar los datos directamente en lugar de leerlos de un archivo
    if (EVP_DigestUpdate(ctx, data, data_length) != 1) {
        fprintf(stderr, "Error al actualizar el hash con los datos\n");
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
    unsigned int final_len;
    if (EVP_DigestFinal_ex(ctx, hmac, &final_len) != 1) {
        fprintf(stderr, "Error al finalizar el hash\n");
        exit(EXIT_FAILURE);
    }

    // Liberar el contexto del hash
    EVP_MD_CTX_free(ctx);
}


void checkhmac(unsigned char *key, int keysz, unsigned char *buf, int sz, unsigned char *h1)
{
    unsigned char h2[SHA1_DIGEST_SIZE];
    unsigned int hsize;

    if (!HMAC(EVP_sha1(), key, keysz, buf, sz, h2, &hsize)) {
        fprintf(stderr, "HMAC failed\n");
        exit(EXIT_FAILURE);
    }
    if (hsize != SHA1_DIGEST_SIZE) {
        fprintf(stderr, "size not valid\n");
        exit(EXIT_FAILURE);
    }
    if (memcmp(h1, h2, SHA1_DIGEST_SIZE) != 0) {
        fprintf(stderr, "ERROR: hmac does not match!\n");
        exit(EXIT_FAILURE);
    }
}

uint64_t receiveNonce(int sockfd) {
    uint64_t nonce;
    recv(sockfd, &nonce, sizeof(nonce), 0);
    return nonce;
}

time_t getCurrentTime() {
    time_t T = time(NULL);
    return T;
}

void concatenateNonceAndTime(uint64_t nonce, time_t T, uint64_t *data, size_t size) {
    data[0] = nonce;
    data[1] = T;
}

void calculateHMAC(unsigned char *key, unsigned char *data, size_t data_len, unsigned char *hmac) {

    // Calculamos la HMAC
    hmacsha1(key, SHA1_DIGEST_SIZE, data, data_len, hmac);
    checkhmac(key, SHA1_DIGEST_SIZE, data, data_len, hmac);
}

void sendDataToServer(int sockfd, unsigned char* hmac, time_t T, char* login) {
    // Enviamos la HMAC al servidor
    send(sockfd, hmac, SHA1_DIGEST_SIZE, 0); // Asumiendo que hmac es de tamaño SHA1_DIGEST_SIZE
    // Enviamos T al servidor
    send(sockfd, &T, sizeof(T), 0);
    // Enviamos el login al servidor
    send(sockfd, login, strlen(login)+1, 0); // Asumiendo que login es una cadena de caracteres terminada en null
}

void receiveServerMessage(int sockfd) {
    // Recibir SUCCESS o FAIL del servidor
    char message[24] = {0};
    recv(sockfd, message, sizeof(message) - 1, 0); // -1 para dejar espacio para el carácter null
    message[sizeof(message) - 1] = '\0'; // Asegurarse de que la cadena esté terminada en null
    printf("%s\n", message);
}

void runClient(char *login, unsigned char *key, char *ip, char *port) {
    struct sockaddr_in sin;
    int sockfd;

    // Crear un socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // Comprobar si el socket se creó correctamente
    if(sockfd < 0) {
        fprintf(stderr, "socket failed\n");
        exit(EXIT_FAILURE);
    }
    // Configurar la dirección y el puerto del socket
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(ip);
    sin.sin_port = htons(atoi(port));
    // Conectar el socket a la dirección y el puerto del servidor
    if(connect(sockfd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
        fprintf(stderr, "connect failed\n");
        exit(EXIT_FAILURE);
    }

    // Aquí puedes manejar la comunicación con el servidor usando sockfd
    // Por ejemplo, puedes enviar y recibir datos usando send() y recv()

    uint64_t nonce = receiveNonce(sockfd);

    // Calcular la HMACSHA1 del nonce concatenado con T (T es un numero entero sin sifgno de 64 bits. Contiene una marca de tiempo con el "tiempo Unix" de la maquina obtenida con la llamada al sistema time(2)) con una key de SHA1_DIGEST_SIZE bytes la cual es argv[0]
    // Primero obtenemos el tiempo actual
    time_t T = getCurrentTime();

    // Luego concatenamos el nonce con T
    uint64_t data[2];
    concatenateNonceAndTime(nonce, T, data, sizeof(data));

    // Luego calculamos la HMACSHA1
    unsigned char hmac[SHA1_DIGEST_SIZE];
    calculateHMAC(key, (unsigned char*)data, sizeof(data), hmac);;

    // Enviar los datos al servidor
    sendDataToServer(sockfd, hmac, T, login);

    // Recibir SUCCESS o FAIL del servidor
    receiveServerMessage(sockfd);
    
    // Cerrar el socket
    close(sockfd);
}

// Funcion para rellenar con ceros login hasta 255 bytes
void rellenarLogin(char *login, char *output) {
    // Inicializar el array a ceros
    memset(output, 0, 255);

    // Copiar el nombre de usuario en el array
    strncpy(output, login, 255);
}

bool argumentsCorrect(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <login> <key> <ip> <puerto>\n", argv[0]);
        return false;
    }
    return true;
}

char* getLogin(char *argv[]) {
    static char login[255];
    rellenarLogin(argv[0], login);
    return login;
}

void hexStringToBytes(char *hexString, unsigned char *byteArray) {
    char *pos = hexString;
    for (size_t count = 0; count < SHA1_DIGEST_SIZE; count++) {
        sscanf(pos, "%2hhx", &byteArray[count]);
        pos += 2;
    }
}

void getKey(char *arg, unsigned char *key) {
    hexStringToBytes(arg, key);
}

int main(int argc, char *argv[]) {
    argc--;
    argv++;
    if (argumentsCorrect(argc, argv)) {
        char *login = getLogin(argv);
        unsigned char key[SHA1_DIGEST_SIZE];
        getKey(argv[1], key);
        char *ip = argv[2];
        char *port = argv[3];
        runClient(login, key, ip, port);
    } else {
        exit(EXIT_FAILURE);
    }
 

    exit (EXIT_SUCCESS);
}