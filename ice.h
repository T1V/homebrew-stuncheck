/*! \file    ice.h
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    ICE/STUN/TURN processing (headers)
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

#ifndef JANUS_ICE_H
#define JANUS_ICE_H
#include <ifaddrs.h>
#include <netinet/in.h>

extern int debug;

typedef struct janus_network_address {
        /*!
         * Should be either \c AF_INET for IPv4 or \c AF_INET6 for IPv6.
         */
        int family;
        union {
                struct in_addr ipv4;
                struct in6_addr ipv6;
        };
} janus_network_address;

int janus_network_address_from_sockaddr(struct sockaddr *s, janus_network_address *a);

int janus_ice_test_stun_server(janus_network_address *addr, uint16_t port,
                               uint16_t local_port, janus_network_address *public_addr, uint16_t *public_port);

#endif
