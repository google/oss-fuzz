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

#include "dhcpd.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  const uint8_t d = *data;
  data += 1;
  size -= 1;

  char *new_str = (char *)malloc(size + 1);
  if (new_str == NULL) {
    return 0;
  }
  memcpy(new_str, data, size);
  new_str[size] = '\0';

  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  struct parse *cfile = NULL;
  if (new_parse(&cfile, -1, new_str, size, filename, 0) == ISC_R_SUCCESS) {

    switch (d % 21) {
    case 0: {
      parse_semi(cfile);
      break;
    }
    case 1: {
      parse_host_name(cfile);
      break;
    }
    case 2: {
      TIME tp;
      parse_lease_time(cfile, &tp);
      break;
    }
    case 3: {
      parse_date(cfile);
      break;
    }
    case 4: {
      // parse_option_space_decl(cfile);
      break;
    }
    case 5: {
      struct executable_statement *e_result = NULL;
      e_result = malloc(sizeof(struct executable_statement));
      memset(e_result, 0, sizeof(struct executable_statement));
      int i_lose;
      parse_on_statement(&e_result, cfile, &i_lose);
      free(e_result);
      break;
    }
    case 6: {
      int i_lose;
      struct executable_statement *e_result2 = NULL;
      e_result2 = malloc(sizeof(struct executable_statement));
      memset(e_result2, 0, sizeof(struct executable_statement));

      parse_non_binary(&e_result2, cfile, &i_lose, 0);
      free(e_result2);
      break;
    }
    case 7: {
      //			parse_key(cfile);
      break;
    }
    case 8: {
      parse_domain_name(cfile);
      break;
    }
    case 9: {
      parse_string(cfile, NULL, NULL);
      break;
    }
    case 10: {
      struct executable_statement *e_result2 = NULL;
      e_result2 = malloc(sizeof(struct executable_statement));
      memset(e_result2, 0, sizeof(struct executable_statement));
      parse_ip_addr_or_hostname(&e_result2, cfile, 0);
      free(e_result2);
      break;
    }
    case 11: {
      struct iaddr ipaddr;
      parse_ip_addr(cfile, &ipaddr);
      break;
    }
    case 12: {
      struct iaddr ipaddr;
      parse_ip6_addr(cfile, &ipaddr);
      break;
    }
    case 13: {
      struct iaddrmatch match;
      parse_ip_addr_with_subnet(cfile, &match);
      break;
    }
    case 14: {
      struct option option;
      memset(&option, 0, sizeof(struct option));
      parse_option_code_definition(cfile, &option);
    }
    case 15: {
      parse_domain_list(cfile, 0);
      break;
    }
    case 16: {
      struct option_cache *oc = NULL;
      oc = malloc(sizeof(struct option_cache));
      if (oc != NULL) {
        parse_option_decl(&oc, cfile);
        free(oc);
      }
      break;
    }
    case 17: {
      struct executable_statement *e_result2 = NULL;
      e_result2 = malloc(sizeof(struct executable_statement));
      memset(e_result2, 0, sizeof(struct executable_statement));

      struct option op;
      memset(&op, 0, sizeof(struct option));

      char *op_name = malloc(5);
      strcpy(op_name, "AAAA");
      op_name[4] = '\0';

      char *op_format = malloc(5);
      strcpy(op_format, "BBBB");
      op_format[0] = '\0';

      op.name = op_name;
      op.format = op_format;
      op.universe = NULL;

      parse_option_statement(&e_result2, cfile, 0, &op, 0);

      free(e_result2);
      free(op_format);
      free(op_name);
      break;
    }
    case 18: {
      struct dns_zone dnsz;
      memset(&dnsz, 0, sizeof(struct dns_zone));
      parse_zone(&dnsz, cfile);
      break;
    }
    case 19: {
      struct executable_statement *e_result2 = NULL;
      e_result2 = malloc(sizeof(struct executable_statement));
      memset(e_result2, 0, sizeof(struct executable_statement));

      int lose2 = 0;

      parse_executable_statement(&e_result2, cfile, &lose2, 0);

      free(e_result2);
    }
    case 20: {
      /*
        struct data_string data;V
        memset(&data, 0, sizeof(struct data_string));
        parse_base64(&data, cfile);
       */
    }
    }
    end_parse(&cfile);
  }

  free(new_str);
  return 0;
}
