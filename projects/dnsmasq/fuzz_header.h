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

#include "dnsmasq.h"

extern void fuzz_blockdata_cleanup();

// Simple garbage collector 
#define GB_SIZE 100

void *pointer_arr[GB_SIZE];
static int pointer_idx = 0;

// If the garbage collector is used then this must be called as first thing
// during a fuzz run.
void gb_init() {
  pointer_idx = 0;

   for (int i = 0; i < GB_SIZE; i++) {
     pointer_arr[i] = NULL;
   }
}

void gb_cleanup() {
  for(int i = 0; i < GB_SIZE; i++) {
    if (pointer_arr[i] != NULL) {
      free(pointer_arr[i]);
    }
  }
}

char *get_null_terminated(const uint8_t **data, size_t *size) {
#define STR_SIZE 75
  if (*size < STR_SIZE || (int)*size < 0) {
    return NULL;
  }

  char *new_s = malloc(STR_SIZE + 1);
  memcpy(new_s, *data, STR_SIZE);
  new_s[STR_SIZE] = '\0';

  *data = *data+STR_SIZE;
  *size -= STR_SIZE;
  return new_s;
}

char *gb_get_random_data(const uint8_t **data, size_t *size, size_t to_get) {
  if (*size < to_get || (int)*size < 0) {
    return NULL;
  }

  char *new_s = malloc(to_get);
  memcpy(new_s, *data, to_get);

  pointer_arr[pointer_idx++] = (void*)new_s;
  
  *data = *data + to_get;
  *size -= to_get;

  return new_s;
}

char *gb_get_null_terminated(const uint8_t **data, size_t *size) {

  char *nstr = get_null_terminated(data, size);
  if (nstr == NULL) {
    return NULL;
  }
  pointer_arr[pointer_idx++] = (void*)nstr;
  return nstr;
}

char *gb_alloc_data(size_t len) {
  char *ptr = calloc(1, len);
  pointer_arr[pointer_idx++] = (void*)ptr;
  
  return ptr;
}

short get_short(const uint8_t **data, size_t *size) {
  if (*size <= 0) return 0;
  short c = (short)(*data)[0];
  *data += 1;
  *size-=1;
  return c;
}

int get_int(const uint8_t **data, size_t *size) {
  if (*size <= 4) return 0;
  const uint8_t *ptr = *data;
  int val = *((int*)ptr);
  *data += 4;
  *size -= 4;
  return val;
}
// end simple garbage collector.

const uint8_t *syscall_data = NULL;
size_t syscall_size = 0;


int fuzz_ioctl(int fd, unsigned long request, void *arg) {
  int fd2 = fd;
  unsigned long request2 = request;
  void *arg_ptr = arg;

  // SIOCGSTAMP
  if (request == SIOCGSTAMP) {
    struct timeval *tv = (struct timeval*)arg_ptr;
    if (tv == NULL) {
      return 0;
    }

    char *rand_tv = gb_get_random_data(&syscall_data, &syscall_size, sizeof(struct timeval));
    if (rand_tv == NULL) {
      return -1;
    }

    memcpy(tv, rand_tv, sizeof(struct timeval));
    return 0;
  }

  if (request == SIOCGIFNAME) {
    //printf("We got a SIOCGIFNAME\n");
    struct ifreq *ifr = (struct ifreq*)arg_ptr;
    if (ifr == NULL) {
      return -1;
    }
    for (int i = 0; i < IF_NAMESIZE; i++) {
      if (syscall_size > 0 && syscall_data != NULL) {
        ifr->ifr_name[i] = (char)*syscall_data;
        syscall_data += 1;
        syscall_size -= 1;
      }
      else {
        ifr->ifr_name[i] = 'A';
      }
    }
    ifr->ifr_name[IF_NAMESIZE-1] = '\0';
    return 0;
    //return -1;
  }
  if (request == SIOCGIFFLAGS) {
    return 0;
  }
  if (request == SIOCGIFADDR) {
    return 0;
  }

  // 
  int retval = ioctl(fd2, request2, arg_ptr); 
  return retval;
}


// Sysytem call wrappers
static char v = 0;
ssize_t fuzz_recvmsg(int sockfd, struct msghdr *msg, int flags) {
  
  struct iovec *target = msg->msg_iov;

  //printf("recvmsg 1 \n");
  if (syscall_size > 1) {
    char r = *syscall_data;
    syscall_data += 1;
    syscall_size -= 1;

    if (r == 12) {
      //printf("recvmsg 2\n");
      return -1;
    }
  }

  int j = 0;
  if (msg->msg_control != NULL) {
    for (;j < CMSG_SPACE(sizeof(struct in_pktinfo)); j++)
    {
      if (syscall_size > 0 && syscall_data != NULL) {
        ((char*)msg->msg_control)[j] = *syscall_data;
        syscall_data += 1;
        syscall_size -= 1;
      }
      else {
        ((char*)msg->msg_control)[j] = 'A';
      }
    }
  }

  int i = 0;
  for (; i < target->iov_len; i++) {
    if (syscall_size > 0 && syscall_data != NULL) {
      ((char*)target->iov_base)[i] = *syscall_data;
      syscall_data += 1;
      syscall_size -= 1;
    }
    else {
      ((char*)target->iov_base)[i] = 'A';
    }
  }

  if (msg->msg_namelen > 0) {
    memset(msg->msg_name, 0, msg->msg_namelen);
  }

  return i;
}


// dnsmasq specific stuff
int init_daemon(const uint8_t **data2, size_t *size2) {
  const uint8_t *data = *data2;
  size_t size = *size2;

  int retval = 0;

#define CLEAN_IF_NULL(arg) if (arg == NULL) goto cleanup;

  // Initialize daemon
  daemon = (struct daemon*)gb_alloc_data(sizeof(struct daemon));
  CLEAN_IF_NULL(daemon)

  // daemon misc
  daemon->max_ttl = get_int(&data, &size);
  daemon->neg_ttl = get_int(&data, &size);
  daemon->local_ttl = get_int(&data, &size);
  daemon->min_cache_ttl = get_int(&data, &size);

  // daemon->namebuff.
  char *daemon_namebuff = gb_get_null_terminated(&data, &size);
  daemon->namebuff = daemon_namebuff;

  // daemon->naptr
  struct naptr *naptr_ptr = (struct naptr*)gb_alloc_data(sizeof(struct naptr));
  char *naptr_name = gb_get_null_terminated(&data, &size);
  char *naptr_replace = gb_get_null_terminated(&data, &size);
  char *naptr_regexp = gb_get_null_terminated(&data, &size);
  char *naptr_services = gb_get_null_terminated(&data, &size);
  char *naptr_flags = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(naptr_ptr)
  CLEAN_IF_NULL(naptr_name)
  CLEAN_IF_NULL(naptr_replace)
  CLEAN_IF_NULL(naptr_regexp)
  CLEAN_IF_NULL(naptr_services)
  CLEAN_IF_NULL(naptr_flags)

  naptr_ptr->name = naptr_name;
  naptr_ptr->replace = naptr_replace;
  naptr_ptr->regexp = naptr_regexp;
  naptr_ptr->services = naptr_services;
  naptr_ptr->flags = naptr_flags;

  daemon->naptr = naptr_ptr;

  // daemon->int_names
  struct interface_name *int_namses = (struct interface_name*)gb_alloc_data(sizeof(struct interface_name));

  char *int_name = gb_get_null_terminated(&data, &size);
  char *int_intr = gb_get_null_terminated(&data, &size);
  CLEAN_IF_NULL(int_namses)
  CLEAN_IF_NULL(int_name)
  CLEAN_IF_NULL(int_intr)
  int_namses->name = int_name;
  int_namses->intr = int_intr;

  struct addrlist *d_addrlist = (struct addrlist*)gb_alloc_data(sizeof(struct addrlist));
  CLEAN_IF_NULL(d_addrlist)
  d_addrlist->flags = get_int(&data, &size);
  d_addrlist->prefixlen = get_int(&data, &size);
  int_namses->addr = d_addrlist;

  daemon->int_names = int_namses;

  if (size > *size2) {
    goto cleanup;
  }

  // daemon->addrbuf
  char *adbuf = gb_alloc_data(200);
  CLEAN_IF_NULL(adbuf)
  daemon->addrbuff = adbuf;

  // daemon->auth_zones
  struct auth_zone *d_az = (struct auth_zone*)gb_alloc_data(sizeof(struct auth_zone));
  char *auth_domain = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(d_az)
  CLEAN_IF_NULL(auth_domain)
  d_az->domain = auth_domain;
  daemon->auth_zones = d_az;

  // deamon->mxnames
  struct mx_srv_record *mx_srv_rec = (struct mx_srv_record*)gb_alloc_data(sizeof(struct mx_srv_record));
  char *mx_name = gb_get_null_terminated(&data, &size);
  char *mx_target = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(mx_srv_rec)
  CLEAN_IF_NULL(mx_target)
  CLEAN_IF_NULL(mx_name)

  mx_srv_rec->next = daemon->mxnames;
  daemon->mxnames = mx_srv_rec;
  mx_srv_rec->name = mx_name;
  mx_srv_rec->target = mx_target;
  mx_srv_rec->issrv = get_int(&data, &size);
  mx_srv_rec->weight = get_int(&data, &size);
  mx_srv_rec->priority = get_int(&data, &size);
  mx_srv_rec->srvport = get_int(&data, &size);
  //data += 40;
  //size -= 40;

  if (size > *size2) {
    goto cleanup;
  }

  // daemon->txt
  struct txt_record *txt_record = (struct txt_record *)gb_alloc_data(sizeof(struct txt_record));
  char *txt_record_name =  gb_get_null_terminated(&data, &size);
  char *txt_record_txt = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(txt_record)
  CLEAN_IF_NULL(txt_record_name)
  CLEAN_IF_NULL(txt_record_txt)

  txt_record->name = txt_record_name;
  txt_record->txt = (unsigned char*)txt_record_txt;
  txt_record->class2 = (get_short(&data, &size) % 10);
  daemon->txt = txt_record;

  // daemon->rr
  struct txt_record *rr_record = (struct txt_record *)gb_alloc_data(sizeof(struct txt_record));
  char *rr_record_name =  gb_get_null_terminated(&data, &size);
  char *rr_record_txt = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(rr_record)
  CLEAN_IF_NULL(rr_record_name)
  CLEAN_IF_NULL(rr_record_txt)

  rr_record->name = rr_record_name;
  rr_record->txt = (unsigned char*)rr_record_txt;
  rr_record->class2 = (get_short(&data, &size) % 10);
  daemon->rr = rr_record;

  if (size > *size2) {
    goto cleanup;
  }

  // daemon->relay4
  //struct dhcp_relay *dr = (struct dhcp_relay*)gb_alloc_data(sizeof(struct dhcp_relay));
  struct dhcp_relay *dr = (struct dhcp_relay*)gb_get_random_data(&data, &size, sizeof(struct dhcp_relay));
  char *dr_interface = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(dr)
  CLEAN_IF_NULL(dr_interface)
  dr->interface = dr_interface;
  dr->next = NULL;
  //dr->current = NULL;
  daemon->relay4 = dr;

  // deamon->bridges
  struct dhcp_bridge *db = (struct dhcp_bridge*)gb_alloc_data(sizeof(struct dhcp_bridge));
  char *db_interface = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(db)
  CLEAN_IF_NULL(db_interface)

  if (strlen(db_interface) > IF_NAMESIZE) {
    for (int i = 0; i < IF_NAMESIZE; i++) {
      db->iface[i] = db_interface[i];
    }
  } else {
    for (int i = 0; i < strlen(db_interface); i++) {
      db->iface[i] = db_interface[i];
    }
  }


  struct dhcp_bridge *db_alias = (struct dhcp_bridge*)gb_alloc_data(sizeof(struct dhcp_bridge));
  //struct dhcp_bridge *db_alias = (struct dhcp_bridge*)gb_get_random_data(&data, &size, sizeof(struct dhcp_bridge));
  char *db_alias_interface = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(db_alias)
  CLEAN_IF_NULL(db_alias_interface)

  if (strlen(db_alias_interface) > IF_NAMESIZE) {
    for (int i = 0; i < IF_NAMESIZE; i++) {
      db_alias->iface[i] = db_alias_interface[i];
    }
  } else {
    for (int i = 0; i < strlen(db_alias_interface); i++) {
      db_alias->iface[i] = db_alias_interface[i];
    }
  }
  db->alias = db_alias;
  daemon->bridges = db;

  // daemon->if_names
  struct iname *in = (struct iname*)gb_get_random_data(&data, &size, sizeof(struct iname));
  char *iname_name = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(in)
  CLEAN_IF_NULL(iname_name)

  in->name = iname_name;
  in->next = NULL;

  daemon->if_names = in;

  // daemon->if_addrs
  struct iname *in_addr = (struct iname*)gb_get_random_data(&data, &size, sizeof(struct iname));
  char *iname_name_addr = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(in_addr)
  CLEAN_IF_NULL(iname_name_addr)

  in_addr->name = iname_name_addr;
  in_addr->next = NULL;

  daemon->if_addrs = in_addr;

  // daemon->if_except
  struct iname *in_except = (struct iname*)gb_get_random_data(&data, &size, sizeof(struct iname));
  char *iname_name_except = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(in_except)
  CLEAN_IF_NULL(iname_name_except)

  in_except->name = iname_name_except;
  in_except->next = NULL;

  daemon->if_except = in_except;

  // daemon->dhcp_except
  struct iname *except = (struct iname*)gb_get_random_data(&data, &size, sizeof(struct iname));
  char *name_except = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(except)
  CLEAN_IF_NULL(name_except)

  except->name = name_except;
  except->next = NULL;

  daemon->dhcp_except = except;

  // daemon->authinterface
  struct iname *auth_interface = (struct iname*)gb_get_random_data(&data, &size, sizeof(struct iname));
  char *auth_name = gb_get_null_terminated(&data, &size);
  
  CLEAN_IF_NULL(auth_interface)
  CLEAN_IF_NULL(auth_name)

  auth_interface->name = auth_name;
  auth_interface->next = NULL;

  daemon->authinterface = auth_interface;


  // daemon->cnames
  struct cname *cn = (struct cname*)gb_alloc_data(sizeof(struct cname));
  char *cname_alias = gb_get_null_terminated(&data, &size);
  char *cname_target = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(cn)
  CLEAN_IF_NULL(cname_alias)
  CLEAN_IF_NULL(cname_target)

  cn->alias = cname_alias;
  cn->target = cname_target;
  daemon->cnames = cn;


  // daemon->ptr
  struct ptr_record *ptr = (struct ptr_record *)gb_alloc_data(sizeof(struct ptr_record));
  CLEAN_IF_NULL(ptr)

  char *ptr_name = gb_get_null_terminated(&data, &size);
  CLEAN_IF_NULL(ptr_name)
  ptr->name = ptr_name;
  daemon->ptr = ptr;

  if (size > *size2) {
    goto cleanup;
  }

  // daemon->dhcp
  struct dhcp_context *dhcp_c = (struct dhcp_context *) gb_get_random_data(&data, &size, sizeof(struct dhcp_context));
  
  char *dhcp_c_temp_in = gb_get_null_terminated(&data, &size);

  struct dhcp_netid *dhcp_c_netid = (struct dhcp_netid *) gb_alloc_data(sizeof(struct dhcp_netid));
  char *dhcp_netid_net = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(dhcp_c)
  CLEAN_IF_NULL(dhcp_c_temp_in)
  CLEAN_IF_NULL(dhcp_c_netid)
  CLEAN_IF_NULL(dhcp_netid_net)

  dhcp_c->next = NULL;
  dhcp_c->current = NULL;
  dhcp_c_netid->net = dhcp_netid_net;
  dhcp_c->filter = dhcp_c_netid;
  dhcp_c->template_interface = dhcp_c_temp_in;

  daemon->dhcp = dhcp_c;


  // daemon->dhcp6
  struct dhcp_context *dhcp6_c = (struct dhcp_context *) gb_get_random_data(&data, &size, sizeof(struct dhcp_context));
  
  char *dhcp6_c_temp_in = gb_get_null_terminated(&data, &size);

  struct dhcp_netid *dhcp6_c_netid = (struct dhcp_netid *) gb_alloc_data(sizeof(struct dhcp_netid));
  char *dhcp6_netid_net = gb_get_null_terminated(&data, &size);

  CLEAN_IF_NULL(dhcp6_c)
  CLEAN_IF_NULL(dhcp6_c_temp_in)
  CLEAN_IF_NULL(dhcp6_c_netid)
  CLEAN_IF_NULL(dhcp6_netid_net)

  dhcp6_c->next = NULL;
  dhcp6_c->current = NULL;
  dhcp6_c_netid->net = dhcp6_netid_net;
  dhcp6_c->filter = dhcp6_c_netid;
  dhcp6_c->template_interface = dhcp6_c_temp_in;

  daemon->dhcp6 = dhcp6_c;

  // daemon->doing_dhcp6
  daemon->doing_dhcp6 = 1;

  // daemon->dhcp_buffs
  char *dhcp_buff = gb_alloc_data(DHCP_BUFF_SZ);
  char *dhcp_buff2 = gb_alloc_data(DHCP_BUFF_SZ);
  char *dhcp_buff3 = gb_alloc_data(DHCP_BUFF_SZ);

  CLEAN_IF_NULL(dhcp_buff)
  CLEAN_IF_NULL(dhcp_buff2)
  CLEAN_IF_NULL(dhcp_buff3)

  daemon->dhcp_buff = dhcp_buff;
  daemon->dhcp_buff2 = dhcp_buff2;
  daemon->dhcp_buff3 = dhcp_buff3;



  // daemon->ignore_addr
  struct bogus_addr *bb = (struct bogus_addr *)gb_alloc_data(sizeof(struct bogus_addr));
  CLEAN_IF_NULL(bb)

  daemon->ignore_addr = bb;

  // daemon->doctors
  if (size > *size2) {
    goto cleanup;
  }

  struct doctor *doctors = (struct doctor *)gb_alloc_data(sizeof(struct doctor));
  CLEAN_IF_NULL(doctors)

  doctors->next = NULL;
  daemon->doctors = doctors;

  retval = 0;
  goto ret;
cleanup:
  retval = -1;

ret:
  return retval;
}
