/*-
 * Copyright (c) 2014 ENEA Software AB
 * Copyright (c) 2014 Nokia
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"

#include "udp_server.h"

#define INVALID_SOCKET  -1
#define SOCKET_ERROR    -1

struct udpecho_s {
	/*socket descriptor */
	int sd;
} udp_echo_cfg;

static void notify(union ofp_sigval *sv)
{
	struct ofp_sock_sigval *ss = (struct ofp_sock_sigval *)sv;
	int s = ss->sockfd;
	int event = ss->event;
	odp_packet_t pkt = ss->pkt;
	int n;
	struct ofp_sockaddr_in addr;
	ofp_socklen_t addr_len = sizeof(addr);

	/*
	 * Only receive events are accepted.
	 */
	if (event != OFP_EVENT_RECV)
		return;

	/*
	 * L2, L3, and L4 pointers are as they were when the packet was
	 * received. L2 and L3 areas may have ancillary data written
	 * over original headers. Only L4 pointer and data after that is valid.
	 * Note that short packets may have padding. Thus odp_packet_length()
	 * may give wrong results. Sender information is over L2 area.
	 * It is best to use function ofp_udp_packet_parse() to
	 * retrieve the information. It also sets the packet's data pointer
	 * to payload and removes padding from the end.
	 */
	uint8_t *p = ofp_udp_packet_parse(pkt, &n,
					    (struct ofp_sockaddr *)&addr,
					    &addr_len);
	/* Pointer and length are not used here. */
	(void)p;
	(void)n;

	/*
	 * There are two alternatives to send a respond.
	 */
#if 1
	/*
	 * Reuse received packet.
	 * Here we want to send the same payload back prepended with "ECHO:".
	 */
	odp_packet_push_head(pkt, 5);
	memcpy(odp_packet_data(pkt), "ECHO:", 5);
	ofp_udp_pkt_sendto(s, pkt, (struct ofp_sockaddr *)&addr, sizeof(addr));
#else
	/*
	 * Send using usual sendto(). Remember to free the packet.
	 */
	ofp_sendto(s, p, r, 0,
		     (struct ofp_sockaddr *)&addr, sizeof(addr));
	odp_packet_free(pkt);
#endif
	/*
	 * Mark ss->pkt invalid to indicate it was released or reused by us.
	 */
	ss->pkt = ODP_PACKET_INVALID;
}

int udpecho_config(void *arg)
{
	ofp_ifnet_t ifnet = OFP_IFNET_INVALID;
	struct ofp_sigevent ev = {0};
	struct ofp_sockaddr_in my_addr;
	uint32_t my_ip_addr;

	(void)arg;

	odp_memset(&udp_echo_cfg, 0, sizeof(udp_echo_cfg));
	udp_echo_cfg.sd = INVALID_SOCKET;

	sleep(1);

	/* Create socket */
	udp_echo_cfg.sd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM,
				     OFP_IPPROTO_UDP);
	if (udp_echo_cfg.sd < 0) {
		OFP_ERR("ofp_socket failed, err='%s'", ofp_strerror(ofp_errno));
		return -1;
	}

	/* Bind it to the address from first interface, port 2048 */
	ifnet = ofp_ifport_ifnet_get(0, OFP_IFPORT_NET_SUBPORT_ITF);
	if (ifnet == OFP_IFNET_INVALID) {
		OFP_ERR("Interface not found.");
		ofp_close(udp_echo_cfg.sd);
		return -1;
	}

	if (ofp_ifnet_ipv4_addr_get(ifnet, OFP_IFNET_IP_TYPE_IP_ADDR,
				    &my_ip_addr)) {
		OFP_ERR("Faile to get IP address.");
		ofp_close(udp_echo_cfg.sd);
		return -1;
	}

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = OFP_AF_INET;
	my_addr.sin_port = odp_cpu_to_be_16(2048);
	my_addr.sin_addr.s_addr = my_ip_addr;
	my_addr.sin_len = sizeof(my_addr);

	if (ofp_bind(udp_echo_cfg.sd, (struct ofp_sockaddr *)&my_addr,
		     sizeof(struct ofp_sockaddr)) < 0) {
		OFP_ERR("ofp_bind failed, err='%s'",
			 ofp_strerror(ofp_errno));
		ofp_close(udp_echo_cfg.sd);
		return -1;
	}

	/* configure sigevent */
	ev.sigev_notify = OFP_SIGEV_HOOK;
	ev.sigev_notify_func = notify;
	ev.sigev_value.sival_ptr = NULL;

	if (ofp_socket_sigevent(udp_echo_cfg.sd, &ev)) {
		OFP_ERR("ofp_socket_sigevent failed, err='%s'",
			ofp_strerror(ofp_errno));
		ofp_close(udp_echo_cfg.sd);
		return -1;
	}

	return 0;
}

int udpecho_cleanup(void)
{
	if (udp_echo_cfg.sd != INVALID_SOCKET) {
		ofp_close(udp_echo_cfg.sd);
		udp_echo_cfg.sd = INVALID_SOCKET;
	}
	return 0;
}

