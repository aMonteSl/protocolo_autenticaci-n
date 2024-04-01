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

enum {
    Sha1sz = 20,
};


void checkhmac(unsigned char *key, int keysz, unsigned char *buf, int sz, unsigned char *h1)
{
    unsigned char h2[Sha1sz];
    unsigned int hsize;

    if (!HMAC(EVP_sha1(), key, keysz, buf, sz, h2, &hsize)) {
        fprintf(stderr, "HMAC failed\n");
        exit(EXIT_FAILURE);
    }
    if (hsize != Sha1sz) {
        fprintf(stderr, "size not valid\n");
        exit(EXIT_FAILURE);
    }
    if (memcmp(h1, h2, Sha1sz) != 0) {
        fprintf(stderr, "ERROR: hmac does not match!\n");
        exit(EXIT_FAILURE);
    }

    // Imprimir un mensaje si la HMAC calculada coincide con la esperada
    printf("HMAC calculada correctamente.\n");
}

uint64_t receiveNonce(int sockfd) {
    uint64_t nonce;
    recv(sockfd, &nonce, sizeof(nonce), 0);
    return nonce;
}

time_t getCurrentTime() {
    time_t T = time(NULL);
    printf("T: %lu\n", T);
    return T;
}

void concatenateNonceAndTime(uint64_t nonce, time_t T, uint64_t *data, size_t size) {
    data[0] = nonce;
    data[1] = T;
    printf("Nonce + T: %lu %lu\n", data[0], data[1]);
    printf("Numero de bytes de la concatenacion: %lu\n", size);
}

void calculateAndPrintHMAC(unsigned char *key, uint64_t *data, size_t size, unsigned char *hmac) {
    HMAC(EVP_sha1(), key, 20, (unsigned char *)data, size, hmac, NULL);
    printf("HMAC: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", hmac[i]);
    }
    printf("\n");
    checkhmac(key, 20, (unsigned char *)data, size, hmac);
}

void sendDataToServer(int sockfd, unsigned char *hmac, time_t T, char *login) {
    send(sockfd, hmac, sizeof(hmac), 0);
    send(sockfd, &T, sizeof(T), 0);
    send(sockfd, login, 255, 0);
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
    printf("Nonce: %lu\n", nonce);

    // Calcular la HMACSHA1 del nonce concatenado con T (T es un numero entero sin sifgno de 64 bits. Contiene una marca de tiempo con el "tiempo Unix" de la maquina obtenida con la llamada al sistema time(2)) con una key de 20 bytes la cual es argv[0]
    // Primero obtenemos el tiempo actual
    time_t T = getCurrentTime();
    // Luego concatenamos el nonce con T
    uint64_t data[2];
    concatenateNonceAndTime(nonce, T, data, sizeof(data));
    // Luego calculamos la HMACSHA1
    unsigned char hmac[20];
    calculateAndPrintHMAC(key, data, sizeof(data), hmac);


    // Enviamos la HMAC al servidor
    send(sockfd, hmac, sizeof(hmac), 0);
    // Enviamos T al servidor
    send(sockfd, &T, sizeof(T), 0);
    // Enviamos el login al servidor
    send(sockfd, login, 255, 0);

    // Recibir SUCCESS o FAIL del servidor
    char message[7];
    recv(sockfd, message, sizeof(message), 0);
    printf("Mensaje del servidor: %s\n", message);
    



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
int main(int argc, char *argv[]) {
    argc--;
    argv++;
    if (argumentsCorrect(argc, argv)) {
        char *login = getLogin(argv);
        unsigned char *key = (unsigned char *)argv[1];
        char *ip = argv[2];
        char *port = argv[3];
        runClient(login, key, ip, port);
    } else {
        exit(EXIT_FAILURE);
    }
 

    exit (EXIT_SUCCESS);
}