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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <mosquitto.h>
#include <mqtt_protocol.h>

#define kMinInputLength 2
#define kMaxInputLength 1024

struct Fuzzer{
    uint16_t    port;    
    int         socket;
    uint8_t*    buffer;
    size_t      size;
    pthread_t   thread;
	bool		killloop;
};
typedef struct Fuzzer Fuzzer;

static int run = -1;

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	if(rc){
		exit(1);
	}else{
		mosquitto_subscribe(mosq, NULL, "request/topic", 0);
	}
}

void on_message_v5(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg, const mosquitto_property *props)
{
	const mosquitto_property *p_resp, *p_corr = NULL;
	char *resp_topic = NULL;

	if(!strcmp(msg->topic, "request/topic")){
		p_resp = mosquitto_property_read_string(props, MQTT_PROP_RESPONSE_TOPIC, &resp_topic, false);
		if(p_resp){
			p_corr = mosquitto_property_read_binary(props, MQTT_PROP_CORRELATION_DATA, NULL, NULL, false);
			mosquitto_publish_v5(mosq, NULL, resp_topic, strlen("a response"), "a response", 0, false, p_corr);
			free(resp_topic);
		}
	}
}

void on_publish(struct mosquitto *mosq, void *obj, int mid)
{
	run = 0;
}


int maincall(Fuzzer *fuzzer)
{
	struct mosquitto *mosq;
	int ver = PROTOCOL_VERSION_v5;

	int port = fuzzer->port;

	mosquitto_lib_init();

	mosq = mosquitto_new("response-test", true, NULL);
	if(mosq == NULL){
		return 1;
	}
	mosquitto_opts_set(mosq, MOSQ_OPT_PROTOCOL_VERSION, &ver);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_publish_callback_set(mosq, on_publish);
	mosquitto_message_v5_callback_set(mosq, on_message_v5);

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
	char peer1_1[] = {
	0x90, 0x04, 0x00, 0x01, 0x00, 0x00 };

    client = accept(fuzzer->socket, (struct sockaddr*)&clientAddr, &clientSZ);


    recv(client, clientData, sizeof(clientData), 0);
    send(client, peer1_0, sizeof(peer1_0), 0);
    recv(client, clientData, sizeof(clientData), 0);

    send(client, peer1_1, sizeof(peer1_1), 0);
    send(client, fuzzer->buffer, fuzzer->size, 0);
    recv(client, clientData, sizeof(clientData), 0);


    shutdown(client,SHUT_RDWR);
    close(client);

	fuzzer->killloop = true;/*To Stop while loop*/
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
{/*mosquitto/test/lib/c/03-request-response-2.c*/

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
