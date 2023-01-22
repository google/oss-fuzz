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
#include <arpa/inet.h>
#include <syscall.h>
#include <sys/ptrace.h>

#include <iostream>

#include "inspect_utils.h"


// Arbitrary domain name resolution.
const std::string kArbitraryDomainNameResolution = "Arbitrary domain name resolution";

// Global constant for one file descriptor about of a DNS socket
int kFdDns = 0;
const size_t kDnsHeaderLen = 12;


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

struct DnsHeader {
  uint16_t tx_id;
  uint16_t flags;
  uint16_t questions;
  uint16_t answers;
  uint16_t nameservers;
  uint16_t additional;
};

struct DnsHeader parse_dns_header(std::vector<std::byte> data) {
  struct DnsHeader h;
  h.tx_id = (((uint16_t) data[0]) << 8) | ((uint16_t) data[1]);
  h.flags = (((uint16_t) data[2]) << 8) | ((uint16_t) data[3]);
  h.questions = (((uint16_t) data[4]) << 8) | ((uint16_t) data[5]);
  h.answers = (((uint16_t) data[6]) << 8) | ((uint16_t) data[7]);
  h.nameservers = (((uint16_t) data[8]) << 8) | ((uint16_t) data[9]);
  h.additional = (((uint16_t) data[10]) << 8) | ((uint16_t) data[11]);
  return h;
}

bool dns_flags_standard_query(uint16_t flags) {
  if ((flags & 0x8000) == 0) {
    // Query, not response.
    if (((flags & 0x7800) >> 11) == 0) {
      // Opcode 0 is standard query.
      if ((flags & 0x0200) == 0) {
        // Message is not truncated.
        if ((flags & 0x0040) == 0) {
          // Z-bit reserved flag is unset.
          return true;
        }
      }
    }
  }
  return false;
}

struct DnsRequest {
  // Start of name in the byte vector.
  size_t offset;
  // End of name in the byte vector.
  size_t end;
  // Length of top level domain.
  uint8_t tld_size;
  // Number of levels/dots in domain name.
  size_t nb_levels;
  // DNS type like A is 1.
  uint16_t dns_type;
  // DNS class like IN is 1.
  uint16_t dns_class;
};

struct DnsRequest parse_dns_request(std::vector<std::byte> data, size_t offset) {
  struct DnsRequest r;
  r.offset = offset;
  r.tld_size = 0;
  r.nb_levels = 0;
  while(offset < data.size()) {
    uint8_t rlen = uint8_t(data[offset]);
    if (rlen == 0) {
      offset++;
      break;
    }
    r.nb_levels++;
    offset += rlen+1;
    r.tld_size = rlen;
  }
  if (offset <= 4 + data.size()) {
    r.end = offset;
    r.dns_type = (((uint16_t) data[offset]) << 8) | ((uint16_t) data[offset+1]);
    r.dns_class = (((uint16_t) data[offset+2]) << 8) | ((uint16_t) data[offset+3]);
  } else {
    r.end = data.size();
  }
  return r;
}

void log_dns_request(struct DnsRequest r, std::vector<std::byte> data) {
  size_t offset = r.offset;
  std::cerr << "===Domain resolved: ";
  while(offset < r.end) {
    uint8_t rlen = uint8_t(data[offset]);
    if (rlen == 0) {
      break;
    }
    std::cerr << '.';
    for (uint8_t i = 1; i < rlen+1; i++) {
      std::cerr << (char) data[offset + i];
    }
    offset += rlen+1;
  }
  std::cerr << "===\n";
  std::cerr << "===DNS request type: " << r.dns_type << ", class: " << r.dns_class << "===\n";
}

void inspect_for_arbitrary_dns_pkt(std::vector<std::byte> data, pid_t pid) {
  if (data.size() < kDnsHeaderLen + 1) {
    return;
  }
  struct DnsHeader h = parse_dns_header(data);
  if (h.questions != 1) {
    return;
  }
  if (h.answers != 0 || h.nameservers != 0) {
    return;
  }
  if (!dns_flags_standard_query(h.flags)) {
    return;
  }

  struct DnsRequest req = parse_dns_request(data, kDnsHeaderLen);
  // Alert if the top level domain is only one character and
  // if there is more than just the TLD.
  if (req.tld_size == 1 && req.nb_levels > 1 && req.end < data.size()) {
    report_bug(kArbitraryDomainNameResolution, pid);
    log_dns_request(req, data);
  }
}

void inspect_for_arbitrary_dns_fdbuffer(pid_t pid, const user_regs_struct &regs) {
  if (kFdDns > 0 && kFdDns == (int) regs.rdi) {
    auto memory = read_memory(pid, regs.rsi, regs.rdx);
    if (memory.size()) {
      inspect_for_arbitrary_dns_pkt(memory, pid);
    }
  }
}

void inspect_for_arbitrary_dns_iov(pid_t pid, unsigned long iov) {
  auto memory = read_memory(pid, iov, sizeof(struct iovec));
  if (memory.size()) {
    struct iovec * iovec = reinterpret_cast<struct iovec *>(memory.data());
    memory = read_memory(pid, (unsigned long) iovec->iov_base, iovec->iov_len);
    if (memory.size()) {
      inspect_for_arbitrary_dns_pkt(memory, pid);
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
