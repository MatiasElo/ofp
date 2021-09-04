/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _OFPI_ICMP_H_
#define _OFPI_ICMP_H_

#include "api/ofp_icmp.h"
#include "api/ofp_types.h"
#include "ofpi_protosw.h"

/*
 * ICMP control block; one per icmp.
 */
struct icmpcb {
	uint16_t		u_seq;	/* ICMP echo sequence. */
	uint64_t		send_timestamp; /* Send time ns*/
};

#define	intoicmpcb(ip)	((struct icmpcb *)(ip)->inp_ppcb)

extern struct pr_usrreqs	ofp_icmp_usrreqs;

void ofp_icmp_init(void);
void ofp_icmp_destroy(void);

enum ofp_return_code ofp_icmp_input(odp_packet_t *pkt_icmp, int off);
enum ofp_return_code ofp_icmp_error(odp_packet_t pkt_in, int type, int code, uint32_t dest, int mtu);

enum ofp_return_code
_ofp_icmp_input(odp_packet_t pkt_icmp, struct ofp_ip *ip, struct ofp_icmp *icp,
		enum ofp_return_code (*reflect)(odp_packet_t pkt));

#endif
