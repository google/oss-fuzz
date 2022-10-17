/* Copyright 2022 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <mosquitto.h>
#include <mqtt_protocol.h>

#define kMinInputLength 5
#define kMaxInputLength 1024

struct Fuzzer{
    uint16_t    port;    
    int         socket;
    uint8_t*    buffer;
    size_t      size;
    pthread_t   thread;
    bool        killloop;
};
typedef struct Fuzzer Fuzzer;

static int run = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
    if(rc){
        exit(1);
    }
}

void on_message_v5(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *properties)
{
    int rc;
    char *str;

    if(properties){
        if(mosquitto_property_read_string(properties, MQTT_PROP_CONTENT_TYPE, &str, false)){
            rc = strcmp(str, "plain/text");
            free(str);

            if(rc == 0){
                if(mosquitto_property_read_string(properties, MQTT_PROP_RESPONSE_TOPIC, &str, false)){
                    rc = strcmp(str, "msg/123");
                    free(str);

                    if(rc == 0){
                        if(msg->qos == 0){
                            mosquitto_publish(mosq, NULL, "ok", 2, "ok", 0, 0);
                            return;
                        }
                    }
                }
            }
        }
    }

    /* No matching message, so quit with an error */
    exit(1);
}

void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
    run = 0;
}

int maincall(Fuzzer *fuzzer)
{
    struct mosquitto *mosq;

    int port = fuzzer->port;

    mosquitto_lib_init();

    mosq = mosquitto_new("prop-test", true, NULL);
    if(mosq == NULL){
        return 1;
    }
    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_message_v5_callback_set(mosq, on_message_v5);
    mosquitto_int_option(mosq, MOSQ_OPT_PROTOCOL_VERSION, MQTT_PROTOCOL_V5);

    mosquitto_connect(mosq, "localhost", port, 60);

    while((run == -1) && (!fuzzer->killloop)){
        mosquitto_loop(mosq, -1, 1);
	}
    mosquitto_destroy(mosq);

    mosquitto_lib_cleanup();
    return run;
}

//Fuzzer Calls

void
fuzzinit(Fuzzer *fuzzer){
    struct sockaddr_in server_addr;
    fuzzer->socket = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(fuzzer->port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    setsockopt(fuzzer->socket, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    bind(fuzzer->socket, (struct sockaddr*)&server_addr, sizeof(server_addr));
    listen(fuzzer->socket,1);
}

void
*Server(void *args){

    Fuzzer *fuzzer = (Fuzzer*)args;

    int client;
    char clientData[10240];
    struct sockaddr_in clientAddr;
    uint32_t clientSZ = sizeof(clientAddr);
    char peer1_0[] = {
    0x20, 0x09, 0x00, 0x00, 0x06, 0x22, 0x00, 0x0a, 
    0x21, 0x00, 0x14 };

    client = accept(fuzzer->socket, (struct sockaddr*)&clientAddr, &clientSZ);

    recv(client, clientData, sizeof(clientData), 0);
    send(client, peer1_0, sizeof(peer1_0), 0);

    send(client, fuzzer->buffer, fuzzer->size, 0);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    recv(client, clientData, sizeof(clientData), 0);


    shutdown(client,SHUT_RDWR);
    close(client);

/*To Stop while loop*/
    fuzzer->killloop = true;

    pthread_exit(NULL);
}

void
clean(Fuzzer *fuzzer){

    shutdown(fuzzer->socket,SHUT_RDWR);
    close(fuzzer->socket);

    free(fuzzer);
}

extern int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{/*mosquitto/test/lib/c/11-prop-recv-qos0.c*/

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    Fuzzer *fuzzer = (Fuzzer*)malloc(sizeof(Fuzzer));
    fuzzer->port = 8000;
    fuzzer->size = Size;
    fuzzer->buffer = (uint8_t *)Data;
    fuzzer->killloop = false;

    fuzzinit(fuzzer);

    pthread_create(&fuzzer->thread, NULL,Server,fuzzer);
    maincall(fuzzer);
    pthread_join(fuzzer->thread, NULL);/* To Avoid UAF*/

    clean(fuzzer);
    return 0;
}
