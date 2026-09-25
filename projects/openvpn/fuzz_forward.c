/* Copyright 2021 Google LLC
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

#include "config.h"

#include <stdint.h>
#include <string.h>

#include "buffer.h"
#include "error.h"
#include "forward.h"
#include "init.h"
#include "socket.h"

static const size_t kMaxPacketSize = 4096;

static void init_context(struct context *ctx, struct link_socket *sock,
                         struct link_socket_addr *socket_addr,
                         struct link_socket_info **socket_infos,
                         struct tuntap *tuntap) {
  memset(ctx, 0, sizeof(*ctx));
  memset(sock, 0, sizeof(*sock));
  memset(socket_addr, 0, sizeof(*socket_addr));
  memset(tuntap, 0, sizeof(*tuntap));

  ctx->options.mode = MODE_POINT_TO_POINT;
  ctx->options.allow_recursive_routing = true;
  ctx->options.disable_dco = true;
  ctx->options.ce.mssfix = 1200;
  ctx->c1.tuntap = tuntap;

  set_check_status(D_LINK_ERRORS, D_LINK_RW);

  ctx->c2.frame.buf.payload_size = kMaxPacketSize;
  ctx->c2.frame.buf.headroom = 256;
  ctx->c2.frame.buf.tailroom = 256;
  ctx->c2.frame.mss_fix = 1200;
  ctx->c2.frame.tun_mtu = 1500;
  ctx->c2.frame.tun_max_mtu = kMaxPacketSize;
  ctx->c2.buffers = init_context_buffers(&ctx->c2.frame);

  sock->sd = SOCKET_UNDEFINED;
  sock->info.lsa = socket_addr;
  sock->info.connection_established = true;
  sock->info.proto = PROTO_UDP;
  sock->info.af = AF_INET;

  socket_addr->actual.dest.addr.in4.sin_family = AF_INET;
  socket_addr->actual.dest.addr.in4.sin_port = htons(1194);
  socket_addr->actual.dest.addr.in4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  socket_infos[0] = &sock->info;
  ctx->c2.link_socket_infos = socket_infos;
  ctx->c2.to_link_addr = &socket_addr->actual;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }

  const uint8_t selector = data[0];
  data++;
  size--;
  if (size > kMaxPacketSize) {
    size = kMaxPacketSize;
  }

  struct context ctx;
  struct link_socket sock;
  struct link_socket_addr socket_addr;
  struct link_socket_info *socket_infos[1];
  struct tuntap tuntap;
  init_context(&ctx, &sock, &socket_addr, socket_infos, &tuntap);

  tuntap.type = (selector & 4) ? DEV_TYPE_TAP : DEV_TYPE_TUN;
  ctx.options.block_ipv6 = (selector & 8) != 0;

  ctx.c2.buf = ctx.c2.buffers->read_tun_buf;
  if (!buf_init(&ctx.c2.buf, ctx.c2.frame.buf.headroom)
      || !buf_write(&ctx.c2.buf, data, size)) {
    free_context_buffers(ctx.c2.buffers);
    return 0;
  }

  switch (selector % 3) {
    case 0:
      process_ip_header(
          &ctx,
          PIP_MSSFIX | PIPV4_PASSTOS | PIPV6_ICMP_NOHOST_CLIENT,
          &ctx.c2.buf,
          &sock);
      break;
    case 1:
      process_incoming_tun(&ctx, &sock);
      break;
    default:
      ctx.c2.to_link = ctx.c2.buf;
      process_outgoing_link(&ctx, &sock);
      break;
  }

  free_context_buffers(ctx.c2.buffers);
  return 0;
}
