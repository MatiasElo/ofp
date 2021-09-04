/* Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


#ifndef _OFPI_ICMP6_H_
#define _OFPI_ICMP6_H_

#include "api/ofp_icmp6.h"
#include "ofpi_vnet.h"
#include "ofpi_ip6_shm.h"

extern struct pr_usrreqs	ofp_icmp6_usrreqs;

/*
void	icmp6_paramerror(struct mbuf *, int);
*/
void	ofp_icmp6_error(odp_packet_t, int, int, int);
void	ofp_icmp6_error2(odp_packet_t, int, int, int, struct ofp_ifnet *);
enum ofp_return_code ofp_icmp6_input(odp_packet_t *, int *, int *);
/*
void	icmp6_fasttimo(void);
void	icmp6_slowtimo(void);
*/
void	ofp_icmp6_reflect(odp_packet_t, size_t);
/*
void	icmp6_prepare(struct mbuf *);
void	icmp6_redirect_input(struct mbuf *, int);
void	icmp6_redirect_output(struct mbuf *, struct rtentry *);

struct	ip6ctlparam;
void	icmp6_mtudisc_update(struct ip6ctlparam *, int);
*/

#define ofp_icmp6_ifstat_inc(ifp, tag)
#define ofp_icmp6_ifoutstat_inc(ifp, type, code)

void ofp_nd6_ns_input(odp_packet_t, int, int);
enum ofp_return_code ofp_nd6_ns_output(struct ofp_ifnet *,
	uint8_t *, uint8_t *);
void ofp_nd6_na_input(odp_packet_t, int, int);
enum ofp_return_code ofp_nd6_na_output(struct ofp_ifnet *,
	uint8_t *, uint8_t *, uint8_t *);

#endif /* not _OFPI_ICMP6_H_ */
