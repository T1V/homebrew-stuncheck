//
//  main.c
//  stuncheck
//
//  Created by Adam Fedor on 10/2/20.
//  Copyright © 2020 T1V. All rights reserved.
//

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <poll.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "ice.h"

typedef struct janus_network_address_string_buffer {
        /*!
         * Should be either \c AF_INET for IPv4 or \c AF_INET6 for IPv6.
         */
        int family;
        union {
                char ipv4[INET_ADDRSTRLEN];
                char ipv6[INET6_ADDRSTRLEN];
        };
} janus_network_address_string_buffer;

int janus_network_address_is_null(const janus_network_address *a) {
        return !a || a->family == AF_UNSPEC;
}

void janus_network_address_string_buffer_nullify(janus_network_address_string_buffer *b) {
        if(b) {
                memset(b, '\0', sizeof(janus_network_address_string_buffer));
                b->family = AF_UNSPEC;
        }
}

int janus_network_address_to_string_buffer(const janus_network_address *a, janus_network_address_string_buffer *buf) {
        if(buf && !janus_network_address_is_null(a)) {
                janus_network_address_string_buffer_nullify(buf);
                buf->family = a->family;
                if(a->family == AF_INET) {
                        return inet_ntop(AF_INET, &a->ipv4, buf->ipv4, INET_ADDRSTRLEN) ? 0 : -errno;
                } else {
                        return inet_ntop(AF_INET6, &a->ipv6, buf->ipv6, INET6_ADDRSTRLEN) ? 0 : -errno;
                }
        } else {
                return -EINVAL;
        }
}

int check_address(const char *address, uint16_t port) {
  uint16_t local_port = 0;
  /* Resolve the address */
  struct addrinfo *res = NULL;
  janus_network_address addr;
  janus_network_address_string_buffer addr_buf;
  if(getaddrinfo(address, NULL, NULL, &res) != 0 ||
     janus_network_address_from_sockaddr(res->ai_addr, &addr) != 0 ||
     janus_network_address_to_string_buffer(&addr, &addr_buf) != 0) {
    printf("Could not resolve %s...\n", address);
    if(res)
      freeaddrinfo(res);
    return -1;
  }
  freeaddrinfo(res);
  
  janus_network_address public_addr = { 0 };
  uint16_t public_port = 0;
  
  if(janus_ice_test_stun_server(&addr, port, local_port, &public_addr, &public_port) < 0) {
    return -1;
  }
  return 0;
}

char * addresses[] = {
  "airconnectrelay.t1v.com",
  "airconnectrelay2.t1v.com",
  NULL,
};

uint16_t ports[] = {
  3478,
  80,
  0
};

int main(int argc, const char * argv[]) {
  
  int arg = 1;
  while (arg < argc) {
    if (strcmp(argv[arg], "-d") == 0) {
      debug = 1;
    }
    arg += 1;
  }
  
  int add = 0;
  int prt = 0;
  while (addresses[add] != NULL) {
    prt = 0;
    while (ports[prt] != 0) {
      printf("* Checking %s:%d...\n", addresses[add], ports[prt]);
      if (check_address(addresses[add], ports[prt]) >= 0) {
        printf("  ok\n");
      } else {
        printf("  FAIL\n");
      }
      prt += 1;
    }
    add += 1;
  }
  return 0;
}
