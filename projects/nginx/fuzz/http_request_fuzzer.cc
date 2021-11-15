// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_http.h>
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "http_request_proto.pb.h"
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

static char configuration[] =
"error_log stderr emerg;\n"
"worker_rlimit_nofile 8192;\n"
"events {\n"
"    use epoll;\n"
"    worker_connections 2;\n"
"    multi_accept off;\n"
"    accept_mutex off;\n"
"}\n"
"http {\n"
"    server_tokens off;\n"
"    default_type application/octet-stream;\n"
"    map $http_upgrade $connection_upgrade {\n"
"      default upgrade;\n"
"      '' close;\n"
"    }\n"
"    error_log stderr emerg;\n"
"    access_log off;\n"
"    map $subdomain $nss {\n"
"      default local_upstream;\n"
"    }\n"
"    upstream local_upstream {\n"
"      server 127.0.0.1:1010 max_fails=0;\n"
"      server 127.0.0.1:1011 max_fails=0;\n"
"      server 127.0.0.1:1012 max_fails=0;\n"
"      server 127.0.0.1:1013 max_fails=0;\n"
"      server 127.0.0.1:1014 max_fails=0;\n"
"      server 127.0.0.1:1015 max_fails=0;\n"
"      server 127.0.0.1:1016 max_fails=0;\n"
"      server 127.0.0.1:1017 max_fails=0;\n"
"      server 127.0.0.1:1018 max_fails=0;\n"
"      server 127.0.0.1:1019 max_fails=0;\n"
"    }\n"
"    client_max_body_size 256M;\n"
"    client_body_temp_path /tmp/;\n"
"    proxy_temp_path /tmp/;\n"
"    proxy_buffer_size 24K;\n"
"    proxy_max_temp_file_size 0;\n"
"    proxy_buffers 8 4K;\n"
"    proxy_busy_buffers_size 28K;\n"
"    proxy_buffering off;\n"
"    server {\n"
"      listen unix:nginx.sock;\n"
"      server_name ~^(?<subdomain>.+)\\.url.com$;\n"
"      proxy_next_upstream off;\n"
"      proxy_read_timeout 5m;\n"
"      proxy_http_version 1.1;\n"
"      proxy_set_header Host $http_host;\n"
"      proxy_set_header X-Real-IP $remote_addr;\n"
"      proxy_set_header X-Real-Port $remote_port;\n"
"      location / {\n"
"        proxy_pass http://$nss;\n"
"        proxy_set_header Host $http_host;\n"
"        proxy_set_header X-Real-IP $remote_addr;\n"
"        proxy_set_header X-Real-Port $remote_port;\n"
"        proxy_set_header Connection '';\n"
"        chunked_transfer_encoding off;\n"
"        proxy_buffering off;\n"
"        proxy_cache off;\n"
"      }\n"
"    }\n"
"}\n"
"\n";


static ngx_cycle_t *cycle;
static ngx_log_t ngx_log;
static ngx_open_file_t ngx_log_file;
static char *my_argv[2];
static char arg1[] = {0, 0xA, 0};

extern char **environ;

static const char *config_file = "/tmp/http_config.conf";

struct fuzzing_data {
  const uint8_t *data;
  size_t data_len;
};

static struct fuzzing_data request;
static struct fuzzing_data reply;

static ngx_http_upstream_t *upstream;
static ngx_http_request_t *req_reply;
static ngx_http_cleanup_t cln_new = {};
static int cln_added;

// Called when finalizing the request to upstream
// Do not need to clean the request pool
static void cleanup_reply(void *data) { req_reply = NULL; }

// Called by the http parser to read the buffer
static ssize_t request_recv_handler(ngx_connection_t *c, u_char *buf,
                                    size_t size) {
  if (request.data_len < size)
    size = request.data_len;
  memcpy(buf, request.data, size);
  request.data += size;
  request.data_len -= size;
  return size;
}

// Feed fuzzing input for the reply from upstream
static ssize_t reply_recv_handler(ngx_connection_t *c, u_char *buf,
                                  size_t size) {
  req_reply = (ngx_http_request_t *)(c->data);
  if (!cln_added) { // add cleanup so that we know whether everything is cleanup
                    // correctly
    cln_added = 1;
    cln_new.handler = cleanup_reply;
    cln_new.next = req_reply->cleanup;
    cln_new.data = NULL;
    req_reply->cleanup = &cln_new;
  }
  upstream = req_reply->upstream;

  if (reply.data_len < size)
    size = reply.data_len;
  memcpy(buf, reply.data, size);
  reply.data += size;
  reply.data_len -= size;
  if (size == 0)
    c->read->ready = 0;
  return size;
}

static ngx_int_t add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags) {
  return NGX_OK;
}

static ngx_int_t init_event(ngx_cycle_t *cycle, ngx_msec_t timer) {
  return NGX_OK;
}

// Used when sending data, do nothing
static ngx_chain_t *send_chain(ngx_connection_t *c, ngx_chain_t *in,
                               off_t limit) {
  c->read->ready = 1;
  c->recv = reply_recv_handler;
  return in->next;
}

// Create a base state for Nginx without starting the server
extern "C" int InitializeNginx(void) {
  ngx_log_t *log;
  ngx_cycle_t init_cycle;

  if (access("nginx.sock", F_OK) != -1) {
    remove("nginx.sock");
  }

  ngx_debug_init();
  ngx_strerror_init();
  ngx_time_init();
  ngx_regex_init();

  // Just output logs to stderr
  ngx_log.file = &ngx_log_file;
  ngx_log.log_level = NGX_LOG_EMERG;
  ngx_log_file.fd = ngx_stderr;
  log = &ngx_log;

  ngx_memzero(&init_cycle, sizeof(ngx_cycle_t));
  init_cycle.log = log;
  ngx_cycle = &init_cycle;

  init_cycle.pool = ngx_create_pool(1024, log);

  // Set custom argv/argc
  my_argv[0] = arg1;
  my_argv[1] = NULL;
  ngx_argv = ngx_os_argv = my_argv;
  ngx_argc = 0;

  // Weird trick to free a leaking buffer always caught by ASAN
  // We basically let ngx overwrite the environment variable, free the leak and
  // restore the environment as before.
  char *env_before = environ[0];
  environ[0] = my_argv[0] + 1;
  ngx_os_init(log);
  free(environ[0]);
  environ[0] = env_before;

  ngx_crc32_table_init();
  ngx_preinit_modules();

  FILE *fptr = fopen(config_file, "w");
  fprintf(fptr, "%s", configuration);
  fclose(fptr);
  init_cycle.conf_file.len = strlen(config_file);
  init_cycle.conf_file.data = (unsigned char *) config_file;

  cycle = ngx_init_cycle(&init_cycle);

  ngx_os_status(cycle->log);
  ngx_cycle = cycle;

  ngx_event_actions.add = add_event;
  ngx_event_actions.init = init_event;
  ngx_io.send_chain = send_chain;
  ngx_event_flags = 1;
  ngx_queue_init(&ngx_posted_accept_events);
  ngx_queue_init(&ngx_posted_next_events);
  ngx_queue_init(&ngx_posted_events);
  ngx_event_timer_init(cycle->log);
  return 0;
}

extern "C" long int invalid_call(ngx_connection_s *a, ngx_chain_s *b,
                                 long int c) {
  return 0;
}

DEFINE_PROTO_FUZZER(const HttpProto &input) {
  static int init = InitializeNginx();
  assert(init == 0);

  // have two free connections, one for client, one for upstream
  ngx_event_t read_event1 = {};
  ngx_event_t write_event1 = {};
  ngx_connection_t local1 = {};
  ngx_event_t read_event2 = {};
  ngx_event_t write_event2 = {};
  ngx_connection_t local2 = {};
  ngx_connection_t *c;
  ngx_listening_t *ls;

  req_reply = NULL;
  upstream = NULL;
  cln_added = 0;

  const char *req_string = input.request().c_str();
  size_t req_len = input.request().size();
  const char *rep_string = input.reply().c_str();
  size_t rep_len = input.reply().size();
  request.data = (const uint8_t *)req_string;
  request.data_len = req_len;
  reply.data = (const uint8_t *)rep_string;
  reply.data_len = rep_len;

  // Use listening entry created from configuration
  ls = (ngx_listening_t *)ngx_cycle->listening.elts;

  // Fake event ready for dispatch on read
  local1.read = &read_event1;
  local1.write = &write_event1;
  local2.read = &read_event2;
  local2.write = &write_event2;
  local2.send_chain = send_chain;

  // Create fake free connection to feed the http handler
  ngx_cycle->free_connections = &local1;
  local1.data = &local2;
  ngx_cycle->free_connection_n = 2;

  // Initialize connection
  c = ngx_get_connection(
      255, &ngx_log); // 255 - (hopefully unused) socket descriptor

  c->shared = 1;
  c->destroyed = 0;
  c->type = SOCK_STREAM;
  c->pool = ngx_create_pool(256, ngx_cycle->log);
  c->sockaddr = ls->sockaddr;
  c->listening = ls;
  c->recv = request_recv_handler; // Where the input will be read
  c->send_chain = send_chain;
  c->send = (ngx_send_pt)invalid_call;
  c->recv_chain = (ngx_recv_chain_pt)invalid_call;
  c->log = &ngx_log;
  c->pool->log = &ngx_log;
  c->read->log = &ngx_log;
  c->write->log = &ngx_log;
  c->socklen = ls->socklen;
  c->local_sockaddr = ls->sockaddr;
  c->local_socklen = ls->socklen;
  c->data = NULL;

  read_event1.ready = 1;
  write_event1.ready = write_event1.delayed = 1;

  // Will redirect to http parser
  ngx_http_init_connection(c);

  // We do not provide working timers or events, and thus we have to manually
  // clean up the requests we created. We do this here.
  // Cross-referencing: https://trac.nginx.org/nginx/ticket/2080#no1).I
  // This is a fix that should be bettered in the future, by creating proper
  // timers and events.
  if (c->destroyed != 1) {
    if (c->read->data != NULL) {
      ngx_connection_t *c2 = (ngx_connection_t*)c->read->data;
        ngx_http_request_t *req_tmp = (ngx_http_request_t*)c2->data;
        req_tmp->cleanup = NULL;
        ngx_http_finalize_request(req_tmp, NGX_DONE);
    }
    ngx_close_connection(c);
  }
}
