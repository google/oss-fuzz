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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>
#include <pwd.h>

int __wrap_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  return 0;
}

int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  return 0;
}

int __wrap_shutdown(int socket, int how) { return 0; }

ssize_t __wrap_listen(int fd, void *buf, size_t bytes) { return 0; }

int __wrap_setsockopt(int fd, int level, int optname, const void *optval,
                      socklen_t optlen) {
  return 0;
}

int __wrap_chmod(const char *pathname, mode_t mode){
  return 0;
}

int __wrap_chown(const char *pathname, uid_t owner, gid_t group){
  return 0;
}

struct passwd pwd;
struct group grp;

struct passwd *__wrap_getpwnam(const char *name){
  pwd.pw_uid = 1;
  return &pwd;
}

struct group *__wrap_getgrnam(const char *name){
  grp.gr_gid = 1;
  return &grp;
}
