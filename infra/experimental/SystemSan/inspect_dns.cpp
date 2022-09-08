/*
 * Copyright 2022 Google LLC

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 *      http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* A detector that uses ptrace to identify shell injection vulnerabilities. */

/* POSIX */
#include <sys/user.h>
#include <unistd.h>

/* Linux */
#include <sys/ptrace.h>
#include <syscall.h>
#include <arpa/inet.h>

#include <iostream>

#include "inspect_utils.h"

// Arbitrary domain name resolution
const std::string kArbitraryDomainNameResolution = "Arbitrary domain name resolution";

// Global constant for one file descriptor about of a DNS socket
int kFdDns = 0;

#define DNS_HEADER_LEN 12


void inspect_for_arbitrary_dns_connect(pid_t pid, const user_regs_struct &regs) {
  auto memory = read_memory(pid, regs.rsi, sizeof(struct sockaddr_in));
  if (memory.size()) {
    struct sockaddr_in * sa = reinterpret_cast<struct sockaddr_in *>(memory.data());
    if (sa->sin_family == AF_INET && htons(sa->sin_port) == 53) {
      // save file descriptor for later sendmmsg
      kFdDns = regs.rdi;
    }
  }
}

void inspect_for_arbitrary_dns_pkt(std::vector<std::byte> data) {
  if (data.size() < DNS_HEADER_LEN + 1) {
    return;
  }
  // Standard query.
  if ((uint8_t(data[2]) & 0xFE) != 0 || uint8_t(data[3]) != 0) {
    return;
  }
  // One question.
  if (uint8_t(data[4]) != 0 || uint8_t(data[5]) != 1) {
    return;
  }
  // Zero answer and other fields.
  for (size_t i = 6; i < DNS_HEADER_LEN; i++) {
    if (uint8_t(data[i]) != 0) {
      return;
    }
  }
  size_t offset = DNS_HEADER_LEN;
  uint8_t tld_size = 0;
  while(offset < data.size()) {
    uint8_t rlen = uint8_t(data[offset]);
    if (rlen == 0) {
      break;
    }
    offset += rlen+1;
    tld_size = rlen;
  }
  // Regular DNS resolution should have 4 more bytes : type and class.
  // Alert if the top level domain is only one character and
  // if there is more than just the TLD.
  if (tld_size == 1 && offset < data.size() && offset > DNS_HEADER_LEN+2) {
    report_bug(kArbitraryDomainNameResolution);
    offset = DNS_HEADER_LEN;
    std::cerr << "===Domain resolved: ";
    while(offset < data.size()) {
      uint8_t rlen = uint8_t(data[offset]);
      if (rlen == 0) {
        break;
      }
      std::cerr << '.';
      for (uint8_t i = 1; i < rlen+1; i++) {
        std::cerr << (char) data[offset + i];
      }
      offset += rlen+1;
      tld_size = rlen;
    }
    std::cerr << "===\n";
  }
}

void inspect_for_arbitrary_dns_fdbuffer(pid_t pid, const user_regs_struct &regs) {
  if (kFdDns > 0 && kFdDns == (int) regs.rdi) {
    auto memory = read_memory(pid, regs.rsi, regs.rdx);
    if (memory.size()) {
      inspect_for_arbitrary_dns_pkt(memory);
    }
  }
}

void inspect_for_arbitrary_dns_iov(pid_t pid, unsigned long iov) {
  auto memory = read_memory(pid, iov, sizeof(struct iovec));
  if (memory.size()) {
    struct iovec * iovec = reinterpret_cast<struct iovec *>(memory.data());
    memory = read_memory(pid, (unsigned long) iovec->iov_base, iovec->iov_len);
    if (memory.size()) {
      inspect_for_arbitrary_dns_pkt(memory);
    }
  }
}

void inspect_for_arbitrary_dns_sendmsg(pid_t pid, const user_regs_struct &regs) {
  if (kFdDns > 0 && kFdDns == (int) regs.rdi) {
    auto memory = read_memory(pid, regs.rsi, sizeof(struct msghdr));
    if (memory.size()) {
      struct msghdr * msg = reinterpret_cast<struct msghdr *>(memory.data());
      if (msg->msg_iovlen == 1) {
        inspect_for_arbitrary_dns_iov(pid, (unsigned long) msg->msg_iov);
      }
    }
  }
}

void inspect_for_arbitrary_dns_sendmmsg(pid_t pid, const user_regs_struct &regs) {
  if (kFdDns > 0 && kFdDns == (int) regs.rdi) {
    auto memory = read_memory(pid, regs.rsi, sizeof(struct mmsghdr));
    if (memory.size()) {
      struct mmsghdr * msg = reinterpret_cast<struct mmsghdr *>(memory.data());
      if (msg->msg_hdr.msg_iovlen == 1) {
        inspect_for_arbitrary_dns_iov(pid, (unsigned long) msg->msg_hdr.msg_iov);
      }
    }
  }
}

void inspect_dns_syscalls(pid_t pid, const user_regs_struct &regs) {
  switch (regs.orig_rax) {
    case __NR_connect:
      inspect_for_arbitrary_dns_connect(pid, regs);
      break;
    case __NR_close:
      if (kFdDns > 0 && kFdDns == (int) regs.rdi) {
        // reset DNS file descriptor on close
        kFdDns = 0;
      }
      break;
    case __NR_sendmmsg:
      inspect_for_arbitrary_dns_sendmmsg(pid, regs);
      break;
    case __NR_sendmsg:
      inspect_for_arbitrary_dns_sendmsg(pid, regs);
      break;
    case __NR_sendto:
      // fallthrough
    case __NR_write:
      inspect_for_arbitrary_dns_fdbuffer(pid, regs);
  }
}
