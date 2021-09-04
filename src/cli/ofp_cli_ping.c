/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include "ofpi_cli.h"
#include "ofpi_util.h"
#include "ofpi_errno.h"
#include "api/ofp_socket.h"
#include "api/ofp_in.h"
#include "api/ofp_in6.h"

#define PING_DATA_SIZE 56

void f_help_ping(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_print(pr, "Ping IP addresses:\r\n"
		"  ping ADDR\r\n\r\n");

	ofp_print(pr, "Ping IPv4 address:\r\n"
		"  ping [-A inet4] IP4ADDR [-C count]\r\n"
		"    IP4ADDR: IP address in a.b.c.d format\r\n"
		"    count: number of packets to send (default 3)\r\n"
		"  Examples:\r\n"
		"    ping 192.168.100.20\r\n"
		"    ping -A inet4 192.168.100.20\r\n\r\n");

	ofp_print(pr, "Ping IPv6 address:\r\n"
		"  ping -A inet6 IP6ADDR\r\n"
		"    IP6ADDR: IP address in a:b:c:d:e:f:g:h or"
		" compressed format\r\n"
		"  Example:\r\n"
		"    ping -A inet6 2000:1baf::1\r\n\r\n");
}

void f_ping(ofp_print_t *pr, const char *s)
{
	struct ofp_sockaddr_in faddr = {0};
	struct ofp_sockaddr_in faddr_rcv = {0};
	ofp_socklen_t faddr_rcv_len;
	uint32_t addr = 0;
	char addr_str[100];
	uint16_t icmp_id = 0;
	char recv_buff[1400];
	struct ofp_icmpdata *icmp_result = NULL;
	int sd = -1;
	uint8_t echobuff[PING_DATA_SIZE]; /* >= sizeof(struct ofp_icmpdata) */
	uint32_t i, cnt;
	ofp_fd_set read_fd;
	struct ofp_timeval timeout;
	int ret_select = 0, ret_sscanf;
	ofp_ssize_t rcv;
	uint64_t pkt_sent = 0;
	uint64_t pkt_recv = 0;
	uint64_t rtt_min = 0;
	uint64_t rtt_max = 0;
	uint64_t rtt_sum = 0;

	ret_sscanf = sscanf(s, "%s %d", addr_str, &cnt);
	if (ret_sscanf < 1) {
		ofp_print(pr, "ping: Invalid address (%s)\r\n\r\n", s);
		return;
	}

	if (ret_sscanf < 2 || cnt <= 0)
		cnt = 3;

	if (!ofp_parse_ip_addr(addr_str, &addr)) {
		ofp_print(pr, "ping: Invalid address (%s)\r\n\r\n", s);
		return;
	}

	sd = ofp_socket(OFP_AF_INET, OFP_SOCK_RAW, OFP_IPPROTO_ICMP);
	if (sd == -1) {
		ofp_print(pr, "ping: socket creation error \r\n\r\n");
		return;
	}

	faddr.sin_len = sizeof(struct ofp_sockaddr_in);
	faddr.sin_family = OFP_AF_INET;
	do {
		odp_random_data((uint8_t *)&icmp_id, sizeof(icmp_id), 0);
	} while (!icmp_id);
	faddr.sin_port = odp_cpu_to_be_16(icmp_id);
	faddr.sin_addr.s_addr = addr;

	if (ofp_connect(sd, (struct ofp_sockaddr *)&faddr, sizeof(faddr))) {
		ofp_print(pr, "ping: failed to set the "
			  "destination address\r\n\r\n");
		ofp_close(sd);
		return;
	}

	odp_random_data(echobuff, sizeof(echobuff), 0);

	OFP_FD_ZERO(&read_fd);

	ofp_print(pr, "PING %s (%s) %d(%d) bytes of data.\r\n",
		  addr_str, addr_str,
		  PING_DATA_SIZE,
		  PING_DATA_SIZE + 20 /* IP header*/ + 8 /* icmp header*/);

	for (i = 0; i < cnt; i++) {
		if (ofp_send(sd, echobuff, sizeof(echobuff), 0) == -1) {
			ofp_print(pr, "ping: failed to send\r\n\r\n");
			ofp_close(sd);
			return;
		}

		pkt_sent++;

		OFP_FD_SET(sd, &read_fd);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		ret_select = ofp_select(sd + 1, &read_fd, NULL, NULL, &timeout);
		if (ret_select == -1) {
			ofp_print(pr, "Failed to select (errno = %d)\r\n",
				  ofp_errno);
			break;
		}

		if (ret_select == 1 && OFP_FD_ISSET(sd, &read_fd)) {
			faddr_rcv_len = sizeof(faddr_rcv);
			rcv = ofp_recvfrom(sd, recv_buff, sizeof(recv_buff), 0,
					   (struct ofp_sockaddr *)&faddr_rcv,
					   &faddr_rcv_len);
			if (rcv == -1) {
				ofp_print(pr, "ping: failed to receive "
					  "message\r\n\r\n");
				continue;
			}

			pkt_recv++;

			if (rcv < (ofp_ssize_t)sizeof(icmp_result)) {
				ofp_print(pr, "ping: failed to receive "
					  "result data\r\n\r\n");
				continue;
			}

			icmp_result = (struct ofp_icmpdata *)recv_buff;
			ofp_print(pr, "%d bytes from %s: icmp_seq=%d ttl=%d "
				"time=%" PRIu64 ".%03" PRIu64 " ms\r\n",
				rcv + 8, /*ICMP header for ECHO*/
				ofp_print_ip_addr(faddr_rcv.sin_addr.s_addr),
				icmp_result->seq, icmp_result->ttl,
				icmp_result->rtt / 1000000,
				icmp_result->rtt / 1000 % 1000);

			rtt_sum += icmp_result->rtt;

			if (icmp_result->rtt <  rtt_min || rtt_min == 0)
				rtt_min = icmp_result->rtt;
			if (icmp_result->rtt >  rtt_max)
				rtt_max = icmp_result->rtt;

			usleep(1000000 - icmp_result->rtt / 1000);
		} else {
			ofp_print(pr, "Destination Unreachable (%d)\r\n", i);
		}
	}

	ofp_print(pr, "\r\n--- %s ping statistics ---\r\n", addr_str);
	ofp_print(pr, "%" PRIu64 " packets transmitted, %" PRIu64 " received, "
		  "%" PRIu64 " errors, %" PRIu64 "%% packet loss\r\n",
		  pkt_sent, pkt_recv, (pkt_sent - pkt_recv),
		  (pkt_sent - pkt_recv) * 100 / pkt_sent);
	if (pkt_recv) {
		uint64_t rtt_avg = rtt_sum / pkt_recv;

		ofp_print(pr, "rtt min/avg/max = "
			"%" PRIu64 ".%03" PRIu64 "/"
			"%" PRIu64 ".%03" PRIu64 "/"
			"%" PRIu64 ".%03" PRIu64 " ms\r\n",
			rtt_min / 1000000, rtt_min / 1000 % 1000,
			rtt_avg / 1000000, rtt_avg / 1000 % 1000,
			rtt_max / 1000000, rtt_max / 1000 % 1000);
	}

	if (ofp_close(sd)) {
		ofp_print(pr, "ping: socket close error \r\n\r\n");
		return;
	}
}

#ifdef INET6
void f_ping_v6(ofp_print_t *pr, const char *s)
{
	struct ofp_sockaddr_in6 faddr = {0};
	struct ofp_sockaddr_in6 faddr_rcv = {0};
	ofp_socklen_t faddr_rcv_len;
	char addr_str[100];
	uint8_t addr[16];
	uint32_t i, cnt;
	uint16_t icmp_id = 0;
	int sd = -1;
	ofp_fd_set read_fd;
	struct ofp_timeval timeout;
	int ret_select = 0, ret_sscanf;
	uint8_t echobuff[PING_DATA_SIZE]; /* >= sizeof(struct ofp_icmpdata) */
	char recv_buff[1400];
	struct ofp_icmpdata *icmp_result = NULL;
	ofp_ssize_t rcv;
	uint64_t pkt_sent = 0;
	uint64_t pkt_recv = 0;
	uint64_t rtt_min = 0;
	uint64_t rtt_max = 0;
	uint64_t rtt_sum = 0;

	ret_sscanf = sscanf(s, "%s %d", addr_str, &cnt);
	if (ret_sscanf < 1) {
		ofp_print(pr, "ping: Invalid address (%s)\r\n\r\n", s);
		return;
	}

	if (ret_sscanf < 2 || cnt <= 0)
		cnt = 3;

	if (!ofp_parse_ip6_addr(addr_str, strlen(addr_str), addr)) {
		ofp_print(pr, "ping: Invalid address (%s)\r\n\r\n", s);
		return;
	}

	sd = ofp_socket(OFP_AF_INET6, OFP_SOCK_RAW, OFP_IPPROTO_ICMPV6);
	if (sd == -1) {
		ofp_print(pr, "ping: socket creation error \r\n\r\n");
		return;
	}

	faddr.sin6_len = sizeof(struct ofp_sockaddr_in6);
	faddr.sin6_family = OFP_AF_INET6;
	do {
		odp_random_data((uint8_t *)&icmp_id, sizeof(icmp_id), 0);
	} while (!icmp_id);
	faddr.sin6_port = odp_cpu_to_be_16(icmp_id);
	odp_memcpy(&faddr.sin6_addr.ofp_s6_addr, addr, 16);

	if (ofp_connect(sd, (struct ofp_sockaddr *)&faddr, sizeof(faddr))) {
		ofp_print(pr, "ping: failed to set the "
			  "destination address\r\n\r\n");
		ofp_close(sd);
		return;
	}

	ofp_print(pr, "PING %s (%s) %d data bytes.\r\n",
		  addr_str, addr_str,
		  PING_DATA_SIZE);

	for (i = 0; i < cnt; i++) {
		if (ofp_send(sd, echobuff, sizeof(echobuff), 0) == -1) {
			ofp_print(pr, "ping: failed to send\r\n\r\n");
			ofp_close(sd);
			return;
		}

		pkt_sent++;

		OFP_FD_SET(sd, &read_fd);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		ret_select = ofp_select(sd + 1, &read_fd, NULL, NULL, &timeout);
		if (ret_select == -1) {
			ofp_print(pr, "Failed to select (errno = %d)\r\n",
				  ofp_errno);
			break;
		}

		if (ret_select == 1 && OFP_FD_ISSET(sd, &read_fd)) {
			faddr_rcv_len = sizeof(faddr_rcv);
			rcv = ofp_recvfrom(sd, recv_buff, sizeof(recv_buff), 0,
					   (struct ofp_sockaddr *)&faddr_rcv,
					   &faddr_rcv_len);
			if (rcv == -1) {
				ofp_print(pr, "ping: failed to receive "
					  "message\r\n\r\n");
				continue;
			}

			pkt_recv++;

			if (rcv < (ofp_ssize_t)sizeof(icmp_result)) {
				ofp_print(pr, "ping: failed to receive "
					  "result data\r\n\r\n");
				continue;
			}

			icmp_result = (struct ofp_icmpdata *)recv_buff;
			ofp_print(pr, "%d bytes from %s: icmp_seq=%d ttl=%d "
				  "time=%" PRIu64 ".%03" PRIu64 " ms\r\n",
				  rcv + 8, /*ICMP header for ECHO*/
				  ofp_print_ip6_addr(faddr_rcv.sin6_addr.ofp_s6_addr),
				  icmp_result->seq, icmp_result->ttl,
				  icmp_result->rtt / 1000000,
				  icmp_result->rtt / 1000 % 1000);

			rtt_sum += icmp_result->rtt;

			if (icmp_result->rtt <  rtt_min || rtt_min == 0)
				rtt_min = icmp_result->rtt;
			if (icmp_result->rtt >  rtt_max)
				rtt_max = icmp_result->rtt;

			usleep(1000000 - icmp_result->rtt / 1000);
		} else {
			ofp_print(pr, "Destination Unreachable (%d)\r\n", i);
		}
	}

	ofp_print(pr, "\r\n--- %s ping statistics ---\r\n", addr_str);
	ofp_print(pr, "%" PRIu64 " packets transmitted, %" PRIu64 " received, "
		  "%" PRIu64 " errors, %" PRIu64 "%% packet loss\r\n",
		  pkt_sent, pkt_recv, (pkt_sent - pkt_recv),
		  (pkt_sent - pkt_recv) * 100 / pkt_sent);

	if (pkt_recv) {
		uint64_t rtt_avg = rtt_sum / pkt_recv;

		ofp_print(pr, "rtt min/avg/max = "
			"%" PRIu64 ".%03" PRIu64 "/"
			"%" PRIu64 ".%03" PRIu64 "/"
			"%" PRIu64 ".%03" PRIu64 " ms\r\n",
			rtt_min / 1000000, rtt_min / 1000 % 1000,
			rtt_avg / 1000000, rtt_avg / 1000 % 1000,
			rtt_max / 1000000, rtt_max / 1000 % 1000);
	}

	if (ofp_close(sd)) {
		ofp_print(pr, "ping: socket close error \r\n\r\n");
		return;
	}
}
#endif /* INET6 */
