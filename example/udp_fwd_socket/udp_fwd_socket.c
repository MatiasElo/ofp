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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ofp.h"
#include "udp_fwd_socket.h"

struct ofp_sockaddr_in *raddr = NULL;
int *sock_array;
int sock_array_size;

static void notify(union ofp_sigval *sv);

static int create_local_sock(int lport, char *laddr_txt)
{
	int sd;
	struct ofp_sockaddr_in laddr = {0};
	struct ofp_sigevent ev;

	/* Create socket*/
	if ((sd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP))
		< 0) {
		OFP_ERR("Error: Failed to create socket: errno = %s!\n",
			 ofp_strerror(ofp_errno));
		return -1;
	}

	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = OFP_AF_INET;
	laddr.sin_port = odp_cpu_to_be_16(lport);
	laddr.sin_addr.s_addr = inet_addr(laddr_txt);
	laddr.sin_len = sizeof(laddr);

	/* Bind to local address*/
	if (ofp_bind(sd, (struct ofp_sockaddr *)&laddr,
		       sizeof(struct ofp_sockaddr)) < 0) {
		OFP_ERR("Error: Failed to bind: addr=%s, port=%d: errno=%s\n",
			laddr_txt, TEST_LPORT, ofp_strerror(ofp_errno));
		ofp_close(sd);
		return -1;
	}

	/* Register callback on socket*/
	ev.sigev_notify = OFP_SIGEV_HOOK;
	ev.sigev_notify_func = notify;
	ev.sigev_value.sival_ptr = NULL;

	if (ofp_socket_sigevent(sd, &ev) == -1) {
		OFP_ERR("Error: Failed configure socket callback: errno = %s\n",
			ofp_strerror(ofp_errno));
		ofp_close(sd);
		return -1;
	}

	return sd;
}

int udp_fwd_cfg(int sock_count, char *laddr_txt, char *raddr_txt)
{
	int port_idx;
	int sd = -1;

	sock_array_size = 0;
	sock_array = (int *)malloc(sock_count * sizeof(int));
	if (sock_array == NULL) {
		OFP_ERR("Error: Failed allocate memory\n");
		return -1;
	}

	for (port_idx = 0; port_idx < sock_count; port_idx++) {
		sd = create_local_sock(TEST_LPORT + port_idx, laddr_txt);
		if (sd == -1)
			return -1;
		sock_array[sock_array_size] = sd;
		sock_array_size++;
	}

	/* Allocate remote address - will be used in notification function*/
	raddr = malloc(sizeof(struct ofp_sockaddr_in));
	if (raddr == NULL) {
		OFP_ERR("Error: Failed allocate memory\n");
		return -1;
	}
	memset(raddr, 0, sizeof(*raddr));
	raddr->sin_family = OFP_AF_INET;
	raddr->sin_port = odp_cpu_to_be_16(TEST_RPORT);
	raddr->sin_addr.s_addr = inet_addr(raddr_txt);
	raddr->sin_len = sizeof(*raddr);

	return 0;
}



static void notify(union ofp_sigval *sv)
{
	struct ofp_sock_sigval *ss = (struct ofp_sock_sigval *)sv;
	int s = ss->sockfd;
	if (ss->event != OFP_EVENT_RECV)
		return;

	ofp_udp_packet_parse(ss->pkt, NULL, NULL, NULL);

	ofp_udp_packet_sendto(s, ss->pkt,
			      (struct ofp_sockaddr *)raddr, sizeof(*raddr));

	/* mark packet as consumed*/
	ss->pkt = ODP_PACKET_INVALID;
}

int udp_fwd_cleanup(void)
{
	int i;

	if (raddr) {
		free(raddr);
		raddr = NULL;
	}

	if (sock_array_size) {
		for (i = 0; i < sock_array_size; i++)
			ofp_close(sock_array[i]);
	}

	if (sock_array) {
		free(sock_array);
		sock_array = NULL;
	}

	return 0;
}

