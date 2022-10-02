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
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <krb5.h>

#define kMinInputLength 10
#define kMaxInputLength 5120
#define PORT 61000

int rdreqFuzz(void);

struct Fuzzer{
    size_t      Size;
    uint8_t*    Data;
    pthread_t   thread;
};
typedef struct Fuzzer Fuzzer;

void *UDPServer(void *args){ 

    Fuzzer *fuzzer = (Fuzzer*)args;

    int socket_desc;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_struct_length = sizeof(client_addr);

    char client_message[kMaxInputLength];
    memset(client_message, '\0', sizeof(client_message));

    socket_desc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    bind(socket_desc, (struct sockaddr*)&server_addr, sizeof(server_addr));

    recvfrom(socket_desc, client_message, sizeof(client_message), 0,
        (struct sockaddr*)&client_addr, &client_struct_length);
            
    sendto(socket_desc, fuzzer->Data, fuzzer->Size, 0,
            (struct sockaddr*)&client_addr, client_struct_length);

    close(socket_desc);
    pthread_exit(NULL);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{//src/tests/rdreq.c

    if (Size < kMinInputLength || Size > kMaxInputLength){
        return 0;
    }

    putenv("KRB5_CONFIG=/out/rdreq/krb5.conf");
    putenv("KRB5CCNAME=/out/rdreq/ccache");

    Fuzzer *fuzzer = (Fuzzer*)malloc(sizeof(Fuzzer));

    fuzzer->Size = Size;
    fuzzer->Data = (uint8_t*)Data;
 
    pthread_create(&fuzzer->thread, NULL,UDPServer,fuzzer);
    rdreqFuzz();
    pthread_join(fuzzer->thread, NULL); /* Avoid UAF*/
 
    free(fuzzer);

    return 0;
}

int rdreqFuzz(){

    krb5_context context;
    krb5_principal client_princ, tkt_princ, server_princ;
    krb5_ccache ccache;
    krb5_creds *cred, mcred;
    krb5_auth_context auth_con;
    krb5_data apreq;
    krb5_error_code ret;
    const char *tkt_name, *server_name;

    tkt_name = "host/2@K";
    server_name = "host/2@K";

    krb5_init_context(&context);

    /* Parse the requested principal names. */
    krb5_parse_name(context, tkt_name, &tkt_princ);
    krb5_parse_name(context, server_name, &server_princ);
    server_princ->type = KRB5_NT_SRV_HST;

    /* Produce an AP-REQ message. */
    krb5_cc_default(context, &ccache);
    krb5_cc_get_principal(context, ccache, &client_princ);

    memset(&mcred, 0, sizeof(mcred));
    mcred.client = client_princ;
    mcred.server = tkt_princ;

//UDP-Protocol
    if (krb5_get_credentials(context, 0, ccache, &mcred, &cred) != 0)
        return 1;
    auth_con = NULL;
    if (krb5_mk_req_extended(context, &auth_con, 0, NULL, cred, &apreq) != 0)
        return 1;

    /* Consume the AP-REQ message without using a replay cache. */
    krb5_auth_con_free(context, auth_con);
    if (krb5_auth_con_init(context, &auth_con) != 0)
        return 1;
    if (krb5_auth_con_setflags(context, auth_con, 0) != 0)
        return 1;
    ret = krb5_rd_req(context, &auth_con, &apreq, server_princ, NULL, NULL,
                      NULL);

    krb5_free_data_contents(context, &apreq);
    assert(apreq.length == 0);
    krb5_auth_con_free(context, auth_con);
    krb5_free_creds(context, cred);
    krb5_cc_close(context, ccache);
    krb5_free_principal(context, client_princ);
    krb5_free_principal(context, tkt_princ);
    krb5_free_principal(context, server_princ);
    krb5_free_context(context);
    return ret;
}
