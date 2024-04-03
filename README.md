# Protocolo de Autenticación

## Compilar

- El cliente se compila con el siguiente comando en shell:
```bash
gcc -Wall -Wvla authclient.c -lssl -lcrypto -o authclient
```
- El servidor se compila con el siguiente comando en shell:
```bash
gcc -Wall -Wvla authserver.c -lssl -lcrypto -o authserver
```

## Ejecutar

- El cliente debe de ejecutarse pasando los siguientes argumentos en el siguiente orden: Login, key, ip_conectarse, puerto_conectarse. Ejemplo:
```bash
./authclient pepe 3f786850e387550fdab836ed7e6dc881de23001b 0.0.0.0 1234
```
- El servidor debe de ejecutarse pasando los siguientes argumentos en el siguiente orden: fichero_cuentas.txt, puerto_escuchando. Ejemplo:
```bash
./authserver accounts.txt 1234
```
- Si el cliente y el servidor están en la misma red lanzados, la ip_conectarse deberá de ser 0.0.0.0, y el cliente se conectara con la dirección ip local_host al servidor

### Autor: Adrián Montes Linares