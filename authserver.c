#include <stdio.h>      // Para printf, fprintf
#include <stdbool.h>    // Para bool
#include <stdlib.h>     // Para exit
#include <stdint.h>     // Para uint64_t
#include <sys/socket.h> // Para las funciones de socket
#include <netinet/in.h> // Para las estructuras de direcciones de Internet
#include <unistd.h>     // Para close, sleep
#include <arpa/inet.h>  // Para las funciones de conversión de direcciones de Internet
#include <time.h>       // Para time_t
#include <string.h>     // Para memcmp, memset, memcpy
#include <openssl/hmac.h> // Para las funciones de HMAC

#define SHA1_BLOCK_SIZE 64 // Tamaño de bloque de SHA-1 en bytes
#define SHA1_DIGEST_SIZE 20 // Tamaño de hash de SHA-1 en bytes

#define FIVE_MINUTES_IN_SECONDS 300 // 5 minutos en segundos

#define LOGIN_SIZE 255 // Tamaño máximo de un login

#define SLEEP_TIME 30 // Tiempo de espera en segundos

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

bool correctArguments(int argc) {
    if (argc < 1) {
        // Si no se pasaron suficientes argumentos, imprimo un mensaje por la salida de error y retorno false
        fprintf(stderr, "No se pasaron suficientes argumentos\n");
        return false;
    }
    return true;
}

bool itsNumber(char *port, int i){
    return (port[i] < '0' || port[i] > '9');
}

bool portItsNumber(char *port) {
    for (int i = 0; port[i] != '\0'; i++) {
        if (itsNumber(port, i)) {
            return false;
        }
    }
    return true;
}

bool portIsValid(char *port) {
    int portNumber = atoi(port);
    if (portNumber < 1024) {
        fprintf(stderr, "El puerto no es un numero valido\n");
        return false;
    }
    return true;
}

bool checkPort(char *port) {
    return portItsNumber(port) && portIsValid(port);
}

bool correctPort(char *port) {
    // Ver si el puerto es un numero Ver si el puerto es un numero valido
    bool correct = checkPort(port);

    return correct;
}

char *managePort(int argc, char *argv[]) {
    char *port;
    if (argc == 1) {
        port = "9999";
    } else {
        port = argv[1];
    }
    return port;
}

uint64_t generateAndSendNonce(int fd) {
    uint64_t nonce;
    nonce = ((uint64_t)rand() << 32) | rand();
    send(fd, &nonce, sizeof(nonce), 0);
    return nonce;
}

void receiveHMAC(int fd, unsigned char* hmac) {
    recv(fd, hmac, SHA1_DIGEST_SIZE, 0);

}

time_t receiveTime(int fd) {
    time_t T;
    recv(fd, &T, sizeof(T), 0);
    return T;
}

void receiveLogin(int fd, char* login) {
    recv(fd, login, LOGIN_SIZE, 0); // Recibir exactamente LOGIN_SIZE bytes
}

bool check_user_exists(char *file, char *login) {
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        fprintf(stderr, "No se pudo abrir el archivo de usuarios.\n");
        return false; // false
    }

    char line[LOGIN_SIZE];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;

        char *line_login = strtok(line, ":");
        if (line_login && strcmp(line_login, login) == 0) {
            fclose(f);
            return true; // true
        }
    }
    // Imprimir un mensaje de error si no se encontró el usuario con el nombre del login
    fprintf(stderr, "No se encontro el usuario con el login %s\n", login);
    fclose(f);
    return false; // false
}

char* findKey(char *file, char *login) {
    if (!check_user_exists(file, login)) {
        return NULL;
    }
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        fprintf(stderr, "No se pudo abrir el archivo\n");
        exit(EXIT_FAILURE);
    }
    char line[LOGIN_SIZE];
    char *key = NULL;
    while (fgets(line, sizeof(line), f)) {
        char *token = strtok(line, ":");
        if (strcmp(token, login) == 0) {
            token = strtok(NULL, ":");
            key = malloc(strlen(token) + 1);
            strcpy(key, token);
            key[strcspn(key, "\n")] = 0;
            break;
        }
    }
    fclose(f);
    if (key == NULL) {
        printf("No se encontro el login\n");
    }
    return key;
}

void concatenateNonceAndTime(uint64_t nonce, time_t T, uint64_t *data, size_t size) {
    data[0] = nonce;
    data[1] = T;

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

bool notOlderThanFiveMin(time_t T) {
    time_t T_server = time(NULL);
    if (T_server - T > FIVE_MINUTES_IN_SECONDS) {
        fprintf(stderr, "El tiempo del cliente es mayor a 5 minutos\n");
        return false;
    }
    return true;
}

void sendSuccess(int fd) {
    char *message = "AUTHENTICATION: SUCCESS";
    send(fd, message, strlen(message), 0);
}

void sendFailure(int fd) {
    char *message = "AUTHENTICATION: FAILURE";
    send(fd, message, strlen(message), 0);
}

void sendResult(int fd, unsigned char *hmac_client, unsigned char *hmacServer) {
    if (memcmp(hmac_client, hmacServer, SHA1_DIGEST_SIZE) == 0) {
        sendSuccess(fd);
    } else {
        sendFailure(fd);

    }
}

void printSuccess(char *login, struct sockaddr_in sin_client) {
    printf("SUCCESS, %s from %s\n", login, inet_ntoa(sin_client.sin_addr));
}

void printFailure(char *login, struct sockaddr_in sin_client) {
    printf("FAILURE, %s from %s\n", login, inet_ntoa(sin_client.sin_addr));
}

void printResult(int fd, unsigned char *hmac_client, unsigned char *hmacServer, char *login) {
    struct sockaddr_in sin_client;
    socklen_t len_client = sizeof(sin_client);
    if (getpeername(fd, (struct sockaddr *)&sin_client, &len_client) == -1) {
        perror("getpeername");
    } else {
        if (memcmp(hmac_client, hmacServer, SHA1_DIGEST_SIZE) == 0) {
            printSuccess(login, sin_client);
        } else {
            printFailure(login, sin_client);
        }
    }
}

void hexStringToBytes(char *hexString, unsigned char *byteArray) {
    char *pos = hexString;
    for (size_t count = 0; count < SHA1_DIGEST_SIZE; count++) {
        sscanf(pos, "%2hhx", &byteArray[count]);
        pos += 2;
    }
}

void handleClientConnection(int fd, char *file) {
    // Generar un nonce y enviarlo al cliente
    uint64_t nonce = generateAndSendNonce(fd);


    // Recibir la HMAC del cliente
    unsigned char hmac_client[SHA1_DIGEST_SIZE];
    receiveHMAC(fd, hmac_client);

    
    // Recibir el tiempo del cliente
    time_t T_client = receiveTime(fd);
    bool notOlder = notOlderThanFiveMin(T_client);

    if (!notOlder) {
        char *message = "FAILURE";
        send(fd, message, strlen(message), 0);
        
    } else{
        // Recibir el login del cliente
        char login[LOGIN_SIZE];
        receiveLogin(fd, login);

        // Buscar la clave del login en el archivo
        char *key = findKey(file, login);

        if (key == NULL) {
            sleep(SLEEP_TIME);
            sendFailure(fd);
            return;
        }
        
        // Concatenar el nonce y el tiempo del cliente
        uint64_t data[2];
        concatenateNonceAndTime(nonce, T_client, data, sizeof(data));


        // Calcular la HMAC de la concatenación del nonce y el tiempo del cliente con la clave
        unsigned char hmacServer[SHA1_DIGEST_SIZE];
        unsigned char keyBytes[SHA1_DIGEST_SIZE];
        hexStringToBytes(key, keyBytes);
        unsigned char *unsigned_data = (unsigned char *)data;

        hmacsha1(keyBytes, SHA1_DIGEST_SIZE, unsigned_data, sizeof(data), hmacServer);
        checkhmac(keyBytes, SHA1_DIGEST_SIZE, unsigned_data, sizeof(data), hmacServer);

        // Enviar resultado al cliente
        sendResult(fd, hmac_client, hmacServer);

        // Imprimir resultado en pantalla
        printResult(fd, hmac_client, hmacServer, login);
    }
    
}

void runServer(char *file, char *port) {
    // Crear un socket
    int sockfd;
    struct sockaddr_in sin;
    struct sockaddr sclient;
    socklen_t addrlen;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // Comprobar si el socket se creó correctamente
    if(sockfd < 0) {
        fprintf(stderr, "socket failed\n");
        exit(EXIT_FAILURE);
    }
    // Configurar la dirección y el puerto del socket
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(atoi(port));
    // Vincular el socket a la dirección y el puerto
    if(bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        fprintf(stderr, "bind failed\n");
        exit(EXIT_FAILURE);
    }

    // Obtener la dirección IP del servidor
    struct sockaddr_in sin_actual;
    socklen_t len = sizeof(sin_actual);
    if (getsockname(sockfd, (struct sockaddr *)&sin_actual, &len) == -1) {
        perror("getsockname");
    } 


    // Escuchar conexiones entrantes en el socket
    if(listen(sockfd, 100) < 0){ //como mucho 100 clientes en la cola
        fprintf(stderr, "listen failed\n");
        exit(EXIT_FAILURE);
    }
    // Bucle infinito para manejar múltiples conexiones
    for(;;){
        addrlen = sizeof(sclient);
        // Aceptar una conexión entrante
        int fd = accept(sockfd, &sclient, &addrlen);
        // Comprobar si la conexión se aceptó correctamente
        if(sockfd < 0){
            fprintf(stderr, "accept failed\n");
            exit(EXIT_FAILURE);
        }

        // Aquí puedes manejar la comunicación con el cliente usando fd
        // Por ejemplo, puedes enviar y recibir datos usando send() y recv()
        pid_t pid = fork();
        if (pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            // Cerrar el socket del servidor en el proceso hijo
            close(sockfd);
            // Manejar la conexión con el cliente
            handleClientConnection(fd, file);
            close(fd);
            exit(EXIT_SUCCESS);
        } else {
            // Cerrar el socket del cliente en el proceso padre
            close(fd);}
        
    }
    // Cerrar el socket del servidor
    close(sockfd);
}

int main(int argc, char *argv[]) {
    argc--; // Decremento el contador de argumentos
    argv++; // Incremento el puntero para que apunte al primer argumento
    // Siempre el .txt va a ser el primer argumento y el puerto el segundo
    // Llamo a una funcion par ver si han sido suficientes los argumentos
    // Si no se pasaron argumentos, termino el programa
    if (!correctArguments(argc)) {
        exit(EXIT_FAILURE);
    }
    // Si se ha pasado un puerto en el segundo argumento, ese sera el puerto, si no, el puerto sera 9999
    char *port = managePort(argc, argv);
    char *file = argv[0];
    // Ver si el puerto es correcto
    if (!correctPort(port)) {
        exit(EXIT_FAILURE);
    }

    runServer(file, port);
    

    return 0;
}