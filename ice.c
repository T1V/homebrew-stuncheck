/*! \file    ice.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    ICE/STUN/TURN processing
 * \details  Implementation (based on libnice) of the ICE process. The
 * code handles the whole ICE process, from the gathering of candidates
 * to the final setup of a virtual channel RTP and RTCP can be transported
 * on. Incoming RTP and RTCP packets from peers are relayed to the associated
 * plugins by means of the incoming_rtp and incoming_rtcp callbacks. Packets
 * to be sent to peers are relayed by peers invoking the relay_rtp and
 * relay_rtcp core callbacks instead.
 *
 * \ingroup protocols
 * \ref protocols
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <poll.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <stun/usages/bind.h>
#include "ice.h"

int debug = 0;

int janus_network_address_from_sockaddr(struct sockaddr *s, janus_network_address *a) {
  if(!s || !a)
    return -EINVAL;
  if(s->sa_family == AF_INET) {
    a->family = AF_INET;
    struct sockaddr_in *addr = (struct sockaddr_in *)s;
    a->ipv4 = addr->sin_addr;
    return 0;
  } else if(s->sa_family == AF_INET6) {
    a->family = AF_INET6;
    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)s;
    a->ipv6 = addr->sin6_addr;
    return 0;
  }
  return -EINVAL;
}

int janus_ice_test_stun_server(janus_network_address *addr, uint16_t port,
                               uint16_t local_port, janus_network_address *public_addr, uint16_t *public_port) {
  if(!addr || !public_addr)
    return -1;
  /* Test the STUN server */
  StunAgent stun;
  stun_agent_init (&stun, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389, 0);
  StunMessage msg;
  uint8_t buf[1500];
  size_t len = stun_usage_bind_create(&stun, &msg, buf, 1500);
  if (debug)
    printf("Testing STUN server: message is of %zu bytes\n", len);
  /* Use the janus_network_address info to drive the socket creation */
  int fd = socket(addr->family, SOCK_DGRAM, 0);
  if(fd < 0) {
    printf("Error creating socket for STUN BINDING test\n");
    return -1;
  }
  struct sockaddr *address = NULL, *remote = NULL;
  struct sockaddr_in address4 = { 0 }, remote4 = { 0 };
  struct sockaddr_in6 address6 = { 0 }, remote6 = { 0 };
  socklen_t addrlen = 0;
  if(addr->family == AF_INET) {
    memset(&address4, 0, sizeof(address4));
    address4.sin_family = AF_INET;
    address4.sin_port = htons(local_port);
    address4.sin_addr.s_addr = INADDR_ANY;
    memset(&remote4, 0, sizeof(remote4));
    remote4.sin_family = AF_INET;
    remote4.sin_port = htons(port);
    memcpy(&remote4.sin_addr, &addr->ipv4, sizeof(addr->ipv4));
    address = (struct sockaddr *)(&address4);
    remote = (struct sockaddr *)(&remote4);
    addrlen = sizeof(remote4);
  } else if(addr->family == AF_INET6) {
    memset(&address6, 0, sizeof(address6));
    address6.sin6_family = AF_INET6;
    address6.sin6_port = htons(local_port);
    address6.sin6_addr = in6addr_any;
    memset(&remote6, 0, sizeof(remote6));
    remote6.sin6_family = AF_INET6;
    remote6.sin6_port = htons(port);
    memcpy(&remote6.sin6_addr, &addr->ipv6, sizeof(addr->ipv6));
    remote6.sin6_addr = addr->ipv6;
    address = (struct sockaddr *)(&address6);
    remote = (struct sockaddr *)(&remote6);
    addrlen = sizeof(remote6);
  }
  if(bind(fd, address, addrlen) < 0) {
    printf("Bind failed for STUN BINDING test: %d (%s)\n", errno, strerror(errno));
    close(fd);
    return -1;
  }
  ssize_t bytes = sendto(fd, buf, len, 0, remote, addrlen);
  if(bytes < 0) {
    printf("Error sending STUN BINDING test\n");
    close(fd);
    return -1;
  }
  if (debug)
    printf("  >> Sent %zd bytes, waiting for reply...\n", bytes);
  struct timeval timeout;
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);
  timeout.tv_sec = 5;	/* FIXME Don't wait forever */
  timeout.tv_usec = 0;
  int err = select(fd+1, &readfds, NULL, NULL, &timeout);
  if(err < 0) {
    printf("Error waiting for a response to our STUN BINDING test: %d (%s)\n", errno, strerror(errno));
    close(fd);
    return -1;
  }
  if(!FD_ISSET(fd, &readfds)) {
    printf("No response to our STUN BINDING test\n");
    close(fd);
    return -1;
  }
  bytes = recvfrom(fd, buf, 1500, 0, remote, &addrlen);
  if (debug)
    printf("  >> Got %zd bytes...\n", bytes);
  close(fd);
  if(bytes < 0) {
    printf("Failed to receive STUN\n");
    return -1;
  }
  if(stun_agent_validate (&stun, &msg, buf, bytes, NULL, NULL) != STUN_VALIDATION_SUCCESS) {
    printf("Failed to validate STUN BINDING response\n");
    return -1;
  }
  StunClass class = stun_message_get_class(&msg);
  StunMethod method = stun_message_get_method(&msg);
  if(class != STUN_RESPONSE || method != STUN_BINDING) {
    printf("Unexpected STUN response: %d/%d\n", class, method);
    return -1;
  }
  StunMessageReturn ret = stun_message_find_xor_addr(&msg, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
  if (debug)
    printf("  >> XOR-MAPPED-ADDRESS: %d\n", ret);
  if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
    if(janus_network_address_from_sockaddr(address, public_addr) != 0) {
      printf("Could not resolve XOR-MAPPED-ADDRESS...\n");
      return -1;
    }
    if(public_port != NULL) {
      if(address->sa_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        *public_port = ntohs(addr->sin_port);
      } else if(address->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
        *public_port = ntohs(addr->sin6_port);
      }
    }
    return 0;
  }
  ret = stun_message_find_addr(&msg, STUN_ATTRIBUTE_MAPPED_ADDRESS, (struct sockaddr_storage *)address, &addrlen);
  if (debug)
    printf("  >> MAPPED-ADDRESS: %d\n", ret);
  if(ret == STUN_MESSAGE_RETURN_SUCCESS) {
    if(janus_network_address_from_sockaddr(address, public_addr) != 0) {
      printf("Could not resolve MAPPED-ADDRESS...\n");
      return -1;
    }
    if(public_port != NULL) {
      if(address->sa_family == AF_INET) {
        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        *public_port = ntohs(addr->sin_port);
      } else if(address->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)address;
        *public_port = ntohs(addr->sin6_port);
      }
    }
    return 0;
  }
  /* No usable attribute? */
  printf("No XOR-MAPPED-ADDRESS or MAPPED-ADDRESS...\n");
  return -1;
}
