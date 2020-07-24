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

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

// Based on the firebase 100k nginx configuration
static char configuration[] =
"error_log stderr emerg;\n"
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
static char arg1[] = { 0, 0xAA, 0 };

extern char **environ;

static char *config_file = "socket_config.conf";

// Create a base state for Nginx without starting the server
int InitializeNginx(void) {
  ngx_log_t *log;
  ngx_cycle_t init_cycle;

  if( access("nginx.sock", F_OK ) != -1 ) {
    remove("nginx.sock");
  }

  ngx_debug_init();
  ngx_strerror_init();
  ngx_time_init();
#if (NGX_PCRE)
  ngx_regex_init();
#endif

  // Just output logs to stderr
  ngx_log.file = &ngx_log_file;
  ngx_log.log_level = NGX_LOG_EMERG;
  ngx_log_file.fd = ngx_stderr;
  log = &ngx_log;

#if (NGX_OPENSSL)
  ngx_ssl_init(log);
#endif
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

  FILE *fptr = fopen("socket_config.conf", "w");
  fprintf(fptr, configuration);
  fclose(fptr);
  init_cycle.conf_file.len = strlen(config_file);
  init_cycle.conf_file.data = (unsigned char *) config_file;

  cycle = ngx_init_cycle(&init_cycle);

  ngx_os_status(cycle->log);
  ngx_cycle = cycle;
  return 0;
}

void invalid_call(void) { }

struct fuzzing_data {
  const uint8_t *data;
  size_t data_len;
};

// Called by the http parser to read the buffer
static ssize_t recv_handler(ngx_connection_t *c, u_char *buf, size_t size) {
  struct fuzzing_data *data = (struct fuzzing_data*)(c->write->data);
  if (data->data_len < size)
    size = data->data_len;
  memcpy(buf, data->data, size);
  data->data += size;
  data->data_len -= size;
  return size;
}


// Used when sending data, do nothing
ngx_chain_t *send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit) {
  return in;
}

int LLVMFuzzerInitialize(int *argc, char ***argv){
  return InitializeNginx();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t data_len) {
  ngx_event_t read_event = {};
  ngx_event_t write_event = {};
  ngx_connection_t local = {};
  ngx_connection_t *c;
  ngx_listening_t *ls;
  struct fuzzing_data fuzz_data;

  fuzz_data.data = data;
  fuzz_data.data_len = data_len;

  // Use listening entry created from configuration
  ls = (ngx_listening_t*)ngx_cycle->listening.elts;

  // Fake event ready for dispatch on read
  local.read = &read_event;
  local.write = &write_event;

  // Create fake free connection to feed the http handler
  ngx_cycle->free_connections = &local;
  ngx_cycle->free_connection_n = 1;

  // Initialize connection
  c = ngx_get_connection(255, &ngx_log);

  c->shared = 1;
  c->type = SOCK_STREAM;
  c->pool = ngx_create_pool(256, ngx_cycle->log);
  c->sockaddr = ls->sockaddr;
  c->listening = ls;
  c->recv = recv_handler;  // Where the input will be read
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

  read_event.ready = 1;
  write_event.data = &fuzz_data;
  write_event.ready = write_event.delayed = 1;

  // Will redirect to http parser
  ngx_http_init_connection(c);

  // Clean-up in case of error
  if (!c->destroyed) {
    ngx_http_free_request((ngx_http_request_t *)(c->data), 0);
    ngx_http_close_connection(c);
  }

  return 0;
}
