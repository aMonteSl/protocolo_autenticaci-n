# protocolo_autenticaci-n

Hay que implementar un cliente y un servidor que ejecuten el siguiente protocolo de autenticación derivado del protocolo CRAM:

1. C←S
 : nonce
2. C calcula r=HMACSHA1(nonce||T,key)

3. C→S
  :  r,T,login

4. S valida r calculando HMACSHA1(nonce||T,key)

5. C←S
 : "SUCCESS" o "FAILURE"

Login es un nombre de usuario, de como mucho 255 caracteres, terminado en un carácter nulo. Siempre se envían 256 bytes para este campo.

Key es una clave de 20 bytes. El servidor tiene que conocer la clave de todos los clientes para autenticarlos.

T es un número entero sin signo 64 bits, little endian. Contiene una marca de tiempo con el "tiempo UNIX" de la máquina obtenida con la llamada al sistema time(2). Se considerará que un mensaje es antiguo si es de hace más de 5 minutos. Esta ventana de tiempo determina el nivel de sincronización de los relojes de cliente y servidor.

Nonce es un número entero sin signo 64 bits, little endian. Su valor debe ser lo más aleatorio posible. El servidor no podrá reutilizar los nonces usados en los últimos 10 minutos.

El resultado final de la autenticación se indica en el mensaje del paso 5, con una cadena de caracteres ASCII, "SUCCESS" si la autenticación es correcta, "FAILURE" si la autenticación es incorrecta. Estas strings tienen que estar acabadas en un carácter nulo.

El protocolo usará TCP. El servidor debe escuchar por omisión en el puerto 9999.

Se debe aplicar un timeout de 30 segundos.

Ejecución

El servidor authserver recibe como argumentos el fichero con las cuentas de los clientes y, opcionalmente, un puerto (si no se pasa el puerto, tiene que escuchar en el puerto 9999). Un ejemplo de ejecución es este:

$ ./authserver accounts.txt 8838

El fichero de cuentas es un fichero de texto con una línea por cada cliente. La línea tiene dos campos: el nombre de usuario (login) y la clave aplanada en hexadecimal. Estos dos campos están separados por dos puntos, por ejemplo:

$ cat accounts.txt
pepe:3f786850e387550fdab836ed7e6dc881de23001b
juan:89e6c98d92887913cadf06b2adb97f26cde4849b
$

Por cada autenticación, debe imprimir por su salida una línea que indique el resultado de la autenticación, indicando la IP del cliente, el login y el resultado de la autenticación, con el siguiente formato:

$ ./authserver accounts.txt 8838
SUCCESS, pepe from 193.147.79.81
FAILURE, juan from 193.147.79.32
...

El servidor no tiene que soportar autenticaciones concurrentes. Una vez que se haya procesado un cliente, pasará al siguiente o quedará esperando a nuevos clientes.

El cliente authclient recibe como argumentos el nombre de cliente, la clave, la dirección del servidor y el puerto. Como salida, debe escribir el resultado de la autenticación. Por ejemplo:

$ ./authclient pepe 3f786850e387550fdab836ed7e6dc881de23001b 193.147.79.11 8838
AUTHENTICATION: SUCCESS
$ ./authclient pepe 3f786850e387550fdab836ed7e6dc881deaaaaaa 193.147.79.11 8838
AUTHENTICATION: FAILURE
$

Si hay errores, debe avisar por la salida de error y terminar con fallo de autenticación. En todos los casos, el programa debe salir con un estatus apropiado.

Los programas en C deben usar una implementación de HMACSHA1 propia basada en la implementación del ejercicio anterior, que utilice la biblioteca openssl para calcular hashes SHA1 (esto es, la implementación de HMACSHA1 debe ser propia).

Si se desea, es posible implementar el cliente en otro lenguaje de programación que no sea C. Es obligatorio implementar el servidor en el lenguaje de programación C. Si se usa otro lenguaje, debe ser posible ejecutar el programa en los laboratorios sin la necesidad de configurar o instalar nada.

Se adjuntan dos ficheros ejecutables (una  implementación de authserver y authclient) para que puedas depurar tus programas fácilmente.

Entrega

Se debe entregar un tgz con el código fuente de authclient y authserver, que contenga un fichero README que incluya instrucciones claras y precisas para compilar y ejecutar los programas.

Sockets: ejemplo de servidor


    int fd, sockfd;
    struct sockaddr_in sin;
    struct sockaddr sclient;
    int port;
    socklen_t addrlen;

    ...

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        err(1, "socket failed");
    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(port);
    if(bind(sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0){
        err(1, "bind failed");
    }
    if(listen(sockfd, 100) < 0){ //como mucho 100 clientes en la cola
        err(1, "listen failed");
    }
    for(;;){
        addrlen = sizeof(sclient);
        fd = accept(sockfd, &sclient, &addrlen);
        if(sockfd < 0){
            err(1, "accept failed");
        }

        ... // usa fd como si fuese un pipe full-duplex

        close(fd);
    }
    close(sockfd);

Sockets: ejemplo de cliente

    struct sockaddr_in sin;
    int sockfd;
    int port;
    char *serverip; // string

 
    ...
 
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        err(1, "socket failed");
    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(serverip);
    sin.sin_port = htons(port);
     if(connect(sockfd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
        err(1, "connect failed");
     }

        ...  // usa sockfd como si fuese un pipe full-duplex

    close(sockfd);

Comprobación de HMAC

Con esta función puedes comprobar si estás sacando bien la HMAC. Recuerda que el código final debe usar tu implementación, no la de openssl.

#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/sha.h>

enum {
    Sha1sz = 20,
};

static void
checkhmac(unsigned char *key, int keysz, unsigned char *buf, int sz, unsigned char *h1)
{
    unsigned char h2[Sha1sz];
    unsigned int hsize;

    if (!HMAC(EVP_sha1(), key, keysz, buf, sz, h2, &hsize)) {
        errx(EXIT_FAILURE, "HMAC failed");
    }
    if (hsize != Sha1sz) {
        errx(EXIT_FAILURE, "size not valid");
    }
    if (memcmp(h1, h2, Sha1sz) != 0) {
        errx(EXIT_FAILURE, "ERROR: hmac does not match!");
    }
}