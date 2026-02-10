/* Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ares.h>

/*
 * Fuzz c-ares channel configuration, initialization, and options handling.
 * The existing fuzzers don't exercise any of the channel init/config code paths.
 *
 * Functions targeted:
 *   - ares_init_options() with varied option combinations
 *   - ares_set_sortlist()
 *   - ares_set_servers_ports_csv()
 *   - ares_get_servers_csv()
 *   - ares_save_options() / ares_destroy_options()
 *   - ares_dup()
 *   - ares_set_local_ip4() / ares_set_local_ip6() / ares_set_local_dev()
 */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4) {
    return 0;
  }

  uint8_t mode = data[0] % 4;
  const uint8_t *payload = data + 1;
  size_t payload_size = size - 1;

  ares_library_init(ARES_LIB_INIT_ALL);

  switch (mode) {
    case 0: {
      /* Fuzz ares_init_options with varied option masks and values */
      if (payload_size < 12) break;

      struct ares_options opts;
      memset(&opts, 0, sizeof(opts));

      /* Extract option values from fuzz input */
      int optmask = 0;
      size_t pos = 0;

      /* Flags */
      uint16_t flag_bits = (payload[pos] << 8) | payload[pos + 1];
      pos += 2;
      opts.flags = flag_bits & 0x7FF; /* Valid flag bits */
      optmask |= ARES_OPT_FLAGS;

      /* Timeout */
      opts.timeout = payload[pos] % 30 + 1; /* 1-30 seconds */
      pos++;
      optmask |= ARES_OPT_TIMEOUT;

      /* Tries */
      opts.tries = (payload[pos] % 10) + 1;
      pos++;
      optmask |= ARES_OPT_TRIES;

      /* Ndots */
      opts.ndots = payload[pos] % 16;
      pos++;
      optmask |= ARES_OPT_NDOTS;

      /* UDP port */
      opts.udp_port = (payload[pos] << 8) | payload[pos + 1];
      pos += 2;
      optmask |= ARES_OPT_UDP_PORT;

      /* TCP port */
      opts.tcp_port = (payload[pos] << 8) | payload[pos + 1];
      pos += 2;
      optmask |= ARES_OPT_TCP_PORT;

      /* Conditionally enable some options based on remaining data */
      if (payload[pos] & 0x01) optmask |= ARES_OPT_ROTATE;
      if (payload[pos] & 0x02) optmask |= ARES_OPT_EDNSPSZ;
      if (payload[pos] & 0x04) {
        opts.ednspsz = 512 + (payload[pos + 1] % 4096);
      }
      if (payload[pos] & 0x08) optmask |= ARES_OPT_NOROTATE;
      pos += 2;

      /* Try to init channel with these options */
      ares_channel_t *channel = NULL;
      int status = ares_init_options(&channel, &opts, optmask);
      if (status == ARES_SUCCESS) {
        /* Exercise save/destroy options round-trip */
        struct ares_options saved_opts;
        int saved_mask;
        if (ares_save_options(channel, &saved_opts, &saved_mask) == ARES_SUCCESS) {
          ares_destroy_options(&saved_opts);
        }

        /* Exercise ares_dup */
        ares_channel_t *dup_channel = NULL;
        if (ares_dup(&dup_channel, channel) == ARES_SUCCESS) {
          ares_destroy(dup_channel);
        }

        /* Exercise get_servers_csv */
        char *servers = ares_get_servers_csv(channel);
        if (servers) {
          ares_free_string(servers);
        }

        /* Exercise queue_active_queries */
        (void)ares_queue_active_queries(channel);

        ares_destroy(channel);
      }
      break;
    }

    case 1: {
      /* Fuzz ares_set_sortlist with varied sort list strings */
      ares_channel_t *channel = NULL;
      if (ares_init(&channel) != ARES_SUCCESS) break;

      /* Null-terminate the payload as a sortlist string */
      size_t str_len = payload_size;
      if (str_len > 512) str_len = 512;
      char *sortstr = (char *)malloc(str_len + 1);
      if (!sortstr) {
        ares_destroy(channel);
        break;
      }
      memcpy(sortstr, payload, str_len);
      sortstr[str_len] = '\0';

      /* Exercise ares_set_sortlist - parses CIDR notation addresses */
      (void)ares_set_sortlist(channel, sortstr);

      free(sortstr);
      ares_destroy(channel);
      break;
    }

    case 2: {
      /* Fuzz ares_set_servers_ports_csv (complements existing CSV fuzzing) */
      ares_channel_t *channel = NULL;
      if (ares_init(&channel) != ARES_SUCCESS) break;

      size_t str_len = payload_size;
      if (str_len > 512) str_len = 512;
      char *csv = (char *)malloc(str_len + 1);
      if (!csv) {
        ares_destroy(channel);
        break;
      }
      memcpy(csv, payload, str_len);
      csv[str_len] = '\0';

      /* Exercise ports CSV variant */
      (void)ares_set_servers_ports_csv(channel, csv);

      /* Get servers back */
      char *servers = ares_get_servers_csv(channel);
      if (servers) {
        ares_free_string(servers);
      }

      free(csv);
      ares_destroy(channel);
      break;
    }

    case 3: {
      /* Fuzz local IP/device configuration */
      ares_channel_t *channel = NULL;
      if (ares_init(&channel) != ARES_SUCCESS) break;

      if (payload_size >= 4) {
        /* Set local IPv4 */
        unsigned int local_ip4;
        memcpy(&local_ip4, payload, 4);
        ares_set_local_ip4(channel, local_ip4);
      }

      if (payload_size >= 20) {
        /* Set local IPv6 */
        ares_set_local_ip6(channel, payload + 4);
      }

      if (payload_size >= 21) {
        /* Set local device name */
        size_t dev_len = payload_size - 20;
        if (dev_len > 63) dev_len = 63;
        char devname[64];
        memcpy(devname, payload + 20, dev_len);
        devname[dev_len] = '\0';
        ares_set_local_dev(channel, devname);
      }

      /* Exercise version and threadsafety queries */
      int version_num;
      const char *version = ares_version(&version_num);
      (void)version;
      (void)ares_threadsafety();
      (void)ares_queue_active_queries(channel);

      ares_destroy(channel);
      break;
    }
  }

  ares_library_cleanup();
  return 0;
}
