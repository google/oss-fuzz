
/*
 * Copyright (C) Andrey Zelenkov
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_http.h>


static ngx_int_t ngx_conf_test_add_quit_event(ngx_cycle_t *cycle);
static void ngx_set_ngx_quit();


static ngx_core_module_t  ngx_regex_module_ctx = {
    ngx_string("conf_test"),
    NULL,
    NULL
};


ngx_module_t  ngx_conf_test_module = {
    NGX_MODULE_V1,
    &ngx_regex_module_ctx,         /* module context */
    NULL,                          /* module directives */
    NGX_CORE_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_conf_test_add_quit_event,  /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_conf_test_add_quit_event(ngx_cycle_t *cycle)
{
   static ngx_event_t           ev;
   static ngx_connection_t      dumb;

   ev.handler = ngx_set_ngx_quit;
   ev.log = cycle->log;
   ev.data = &dumb;
   dumb.fd = (ngx_socket_t) -1;

   ngx_add_timer(&ev, 0);

   ngx_post_event(&ev, &ngx_posted_events);

   return NGX_OK;
}


static void
ngx_set_ngx_quit()
{
   ngx_quit = 1;
}
