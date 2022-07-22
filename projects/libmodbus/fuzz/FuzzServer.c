#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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
int server(Fuzzer *fuzzer);

void fuzzinit(Fuzzer *fuzzer){

    {//File
        fuzzer->inFile = fopen(fuzzer->file,"rb");

        fseek(fuzzer->inFile, 0L, SEEK_END);
        fuzzer->size = ftell(fuzzer->inFile);
        fseek(fuzzer->inFile, 0L, SEEK_SET);

        fuzzer->buffer = (uint8_t*)calloc(fuzzer->size, sizeof(char));

        fread(fuzzer->buffer, sizeof(char), fuzzer->size, fuzzer->inFile);
    }
}

void *client(void *args){ 

    Fuzzer *fuzzer = (Fuzzer*)args;
    int sockfd;
    struct sockaddr_in serv_addr;
    //char buffer[10240] = { 0 };

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(fuzzer->port);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    while(1){
        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
            continue;
        }else{
            break;
        }
    }

    send(sockfd,fuzzer->buffer,fuzzer->size,0);
    //recv(sockfd,buffer,sizeof(buffer),0);

    close(sockfd);
    pthread_exit(NULL);
}

void clean(Fuzzer *fuzzer){
    {//File
        free(fuzzer->buffer);
        fclose(fuzzer->inFile);
    }
    free(fuzzer);
}

#ifdef LIB_FUZZER

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    if(size < MinSize){
        return 1;
    }

    Fuzzer *fuzzer = (Fuzzer*)malloc(sizeof(Fuzzer));
    fuzzer->port = 8080;    //port

    fuzzer->size = size;
    fuzzer->buffer = data;

    pthread_create(&fuzzer->thread, NULL,client,fuzzer);
    server(fuzzer);
    pthread_join(fuzzer->thread, NULL);

    free(fuzzer);
    return 0;
}
#else
int main(int argc, char *argv[]){

    if(argc < 3){
        printf("Server-port,Input-file \n");
        return 0;
    }

    Fuzzer *fuzzer = (Fuzzer*)malloc(sizeof(Fuzzer));
    fuzzer->port = atoi(argv[1]);
    fuzzer->file = argv[2];

    fuzzinit(fuzzer);

    if(fuzzer->size < MinSize){
        clean(fuzzer);
        return 1;
    }

    pthread_create(&fuzzer->thread, NULL,client,fuzzer);

    server(fuzzer);

    clean(fuzzer);

    return 0;
}
#endif

int server(Fuzzer *fuzzer)
{
    int s = -1;
    modbus_t *ctx;
    modbus_mapping_t *mb_mapping;
    int rc;
    int i;
    uint8_t *query;

    ctx = modbus_new_tcp("127.0.0.1", fuzzer->port);
    query = malloc(MODBUS_TCP_MAX_ADU_LENGTH);

    mb_mapping = modbus_mapping_new_start_address(
        UT_BITS_ADDRESS, UT_BITS_NB,
        UT_INPUT_BITS_ADDRESS, UT_INPUT_BITS_NB,
        UT_REGISTERS_ADDRESS, UT_REGISTERS_NB_MAX,
        UT_INPUT_REGISTERS_ADDRESS, UT_INPUT_REGISTERS_NB);
    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n",
                modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    /* Examples from PI_MODBUS_300.pdf.
       Only the read-only input values are assigned. */

    /* Initialize input values that's can be only done server side. */
    modbus_set_bits_from_bytes(mb_mapping->tab_input_bits, 0, UT_INPUT_BITS_NB,
                               UT_INPUT_BITS_TAB);

    /* Initialize values of INPUT REGISTERS */
    for (i=0; i < UT_INPUT_REGISTERS_NB; i++) {
        mb_mapping->tab_input_registers[i] = UT_INPUT_REGISTERS_TAB[i];
    }

    s = modbus_tcp_listen(ctx, 1);
    modbus_tcp_accept(ctx, &s);

    rc = modbus_receive(ctx, query);

    if (s != -1) {
        close(s);
    }

    modbus_mapping_free(mb_mapping);
    free(query);
    /* For RTU */
    modbus_close(ctx);
    modbus_free(ctx);

    return rc;
}
