// Primero voy a hacer que el servidor reciba los argumentos de la linea de comandos
// y luego voy a hacer que el servidor reciba los mensajes de los clientes y los imprima
// en pantalla.
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h> // Include the necessary header file
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h> 
#include <string.h> // Para memcmp
#include <openssl/hmac.h>


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

void openFile(char *file) {
    // Abrir el fichero e imprimir el contenido del archivo
    FILE *f = fopen(file, "r");
    if (f == NULL) {
        fprintf(stderr, "No se pudo abrir el archivo\n");
        exit(EXIT_FAILURE);
    }
    char c;
    while ((c = fgetc(f)) != EOF) {
        printf("%c", c);
    }
    fclose(f);
    
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
    } else {
        printf("La ip del servidor es: %s\n", inet_ntoa(sin_actual.sin_addr));
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

        // Primero, nada mas conectarse un cliente hay que envicarle un Nonce es un número entero sin signo 64 bits, little endian. Su valor debe ser lo más aleatorio posible. El servidor no podrá reutilizar los nonces usados en los últimos 10 minutos.
        // Luego, el cliente enviará un mensaje con el nonce cifrado con la clave pública del servidor. El servidor descifrará el mensaje y comprobará que el nonce es correcto.
        // Si el nonce es correcto, el servidor enviará un mensaje con un token cifrado con la clave pública del cliente. El cliente descifrará el mensaje y comprobará que el token es correcto.
        // Si el token es correcto, el cliente enviará un mensaje con el usuario y la contraseña cifrados con la clave pública del servidor. El servidor descifrará el mensaje y comprobará que el usuario y la contraseña son correctos.
        // Crear el nonce aleatoriamente, es un numero de 64 bits sin signo
        uint64_t nonce;
        nonce = ((uint64_t)rand() << 32) | rand();
        printf("Nonce: %lu\n", nonce);
        send(fd, &nonce, sizeof(nonce), 0);


        // Recibit la hmac del cliente
        unsigned char hmac[20];
        recv(fd, hmac, sizeof(hmac), 0);
        printf("HMAC del cliente: ");
        for (int i = 0; i < 20; i++) {
            printf("%02x", hmac[i]);
        }

        // Recibir el tiempo del cliente
        time_t T;
        recv(fd, &T, sizeof(T), 0);
        printf("\nT del cliente: %lu\n", T);

        // Recibir el login del cliente
        char login[255];
        recv(fd, login, sizeof(login), 0);
        printf("Login del cliente: %s\n", login);
        printf("Tamano del login: %lu\n", sizeof(login));

        // Ahora el sevidor tiene que calcular la HMACSHA1 del nonce concatenado con T con una key la cual tenemos
        char *key = "3f786850e387550fdab836ed7e6dc881de23001b";
        uint64_t data[2] = {nonce, T};
        unsigned char hmacServer[20];
        HMAC(EVP_sha1(), key, 20, (unsigned char *)data, sizeof(data), hmacServer, NULL);
        // Imprimir la HMAC
        printf("HMAC del servidor: ");
        for (int i = 0; i < 20; i++) {
            printf("%02x", hmacServer[i]);
        }
        printf("\n");


        // Si la hmac del cliente es igual a la hmac del sevidor, entonces se le envia un mensaje al cliente diciendo SUCCESS, si no FAILURE
        if (memcmp(hmac, hmacServer, 20) == 0) {
            char *message = "SUCCESS";
            send(fd, message, strlen(message), 0);
        } else {
            char *message = "FAILURE";
            send(fd, message, strlen(message), 0);
        }


        printf("\n \n LA CONEXION SE HA FINALIZADO\n");

        // Cerrar la conexión con el cliente
        close(fd);
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
    printf("El puerto es: %s\n", port);
    printf("El archivo es: %s\n", file);

    // Ahora toca abrir el fichero y guardarlo en una estructura de datos
    openFile(file);

    runServer(file, port);
    

    return 0;
}