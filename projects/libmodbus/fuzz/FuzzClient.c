#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <modbus.h>
#include "unit-test.h"

struct Fuzzer{
    uint16_t    port;    
    char*       file;

    FILE*       inFile;
    uint64_t    size;
    uint8_t*    buffer;

    pthread_t   thread;
    int         socket;
};
typedef struct Fuzzer Fuzzer;

#define MinSize 9
#define PORT 8080
int client(Fuzzer *fuzzer);

void fuzzinit(Fuzzer *fuzzer){
#ifndef LIB_FUZZER
    {//File
        fuzzer->inFile = fopen(fuzzer->file,"rb");

        fseek(fuzzer->inFile, 0L, SEEK_END);
        fuzzer->size = ftell(fuzzer->inFile);
        fseek(fuzzer->inFile, 0L, SEEK_SET);

        fuzzer->buffer = (uint8_t*)calloc(fuzzer->size, sizeof(char));

        fread(fuzzer->buffer, sizeof(char), fuzzer->size, fuzzer->inFile);
    }
#endif
    {//Server
        struct sockaddr_in server_addr;
        fuzzer->socket = socket(AF_INET, SOCK_STREAM, 0);

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(fuzzer->port);
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        setsockopt(fuzzer->socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

        bind(fuzzer->socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
        listen(fuzzer->socket,1);
    }
}

void *Server(void *args){

    Fuzzer *fuzzer = (Fuzzer*)args;
    {
        int client;
        char clientData[10240];
        struct sockaddr_in clientAddr;
        uint32_t clientSZ = sizeof(clientAddr);

        client = accept(fuzzer->socket, (struct sockaddr*)&clientAddr, &clientSZ);

        send(client, fuzzer->buffer, fuzzer->size, 0);
        recv(client, clientData, sizeof(clientData), 0);

        send(client, fuzzer->buffer, fuzzer->size, 0);
        recv(client, clientData, sizeof(clientData), 0);

        shutdown(client,SHUT_RDWR);
        close(client);
    }
    pthread_exit(NULL);
}

void clean(Fuzzer *fuzzer){
#ifndef LIB_FUZZER
    {//File
        free(fuzzer->buffer);
        fclose(fuzzer->inFile);
    }
#endif
    {//Server
        shutdown(fuzzer->socket,SHUT_RDWR);
        close(fuzzer->socket);
    }
    free(fuzzer);
}

#ifdef LIB_FUZZER

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if(size < MinSize){
        return 1;
    }

    Fuzzer *fuzzer = (Fuzzer*)malloc(sizeof(Fuzzer));
    fuzzer->port = PORT;

    fuzzer->size = size;
    fuzzer->buffer = data;

    fuzzinit(fuzzer);

    pthread_create(&fuzzer->thread, NULL,Server,fuzzer);
    client(fuzzer);
    pthread_join(fuzzer->thread, NULL);

    clean(fuzzer);
    return 0;
}
#else
int main(int argc, char *argv[]){

    if(argc < 2){
        printf("input-file \n");
        return 0;
    }

    Fuzzer *fuzzer = (Fuzzer*)malloc(sizeof(Fuzzer));
    fuzzer->port = PORT;
    fuzzer->file = argv[1];

    fuzzinit(fuzzer);

    if(fuzzer->size < MinSize){
        clean(fuzzer);
        return 1;
    }

    pthread_create(&fuzzer->thread, NULL,Server,fuzzer);

    client(fuzzer);

    pthread_join(fuzzer->thread, NULL);

    clean(fuzzer);

    return 0;
}
#endif

int client(Fuzzer *fuzzer){// For Testing 

    uint8_t *tab_rp_bits = NULL;
    uint16_t *tab_rp_registers = NULL;
    modbus_t *ctx = NULL;
    int nb_points;
    int rc;

    ctx = modbus_new_tcp("127.0.0.1", fuzzer->port);

    if (ctx == NULL) {
        fprintf(stderr, "Unable to allocate libmodbus context\n");
        return -1;
    }

    if (modbus_connect(ctx) == -1) {
        fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    /* Allocate and initialize the memory to store the bits */
    nb_points = (UT_BITS_NB > UT_INPUT_BITS_NB) ? UT_BITS_NB : UT_INPUT_BITS_NB;
    tab_rp_bits = (uint8_t *) malloc(nb_points * sizeof(uint8_t));
    memset(tab_rp_bits, 0, nb_points * sizeof(uint8_t));

    /* Allocate and initialize the memory to store the registers */
    nb_points = (UT_REGISTERS_NB > UT_INPUT_REGISTERS_NB) ?
        UT_REGISTERS_NB : UT_INPUT_REGISTERS_NB;
    tab_rp_registers = (uint16_t *) malloc(nb_points * sizeof(uint16_t));
    memset(tab_rp_registers, 0, nb_points * sizeof(uint16_t));

//Read
    rc = modbus_read_bits(ctx, UT_BITS_ADDRESS, UT_BITS_NB, tab_rp_bits);

    rc = modbus_read_registers(ctx, UT_REGISTERS_ADDRESS,
                               UT_REGISTERS_NB, tab_rp_registers);

    /* Free the memory */
    free(tab_rp_bits);
    free(tab_rp_registers);

    /* Close the connection */
    modbus_close(ctx);
    modbus_free(ctx);

    return rc;
}
