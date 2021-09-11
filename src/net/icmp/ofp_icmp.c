/*-
 * Copyright (c) 1982, 1986, 1988, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)ip_icmp.c	8.2 (Berkeley) 1/4/94
 */
#include "ofpi.h"
#include "ofpi_icmp_shm.h"
#include "ofpi_pkt_processing.h"
#include "ofpi_protosw.h"
#include "ofpi_socket.h"
#include "ofpi_sockstate.h"
#include "ofpi_socketvar.h"
#include "ofpi_route.h"
#include "ofpi_ifnet_portconf.h"
#include "ofpi_log.h"
#include "ofpi_util.h"
#include "ofpi_errno.h"
/* ODP should have support to get time and date like gettimeofday from Linux*/
#include <sys/time.h>
#include <inttypes.h>
/*
#include <sys/cdefs.h>
__FBSDID("$FreeBSD: release/9.1.0/sys/netinet/ip_icmp.c 237913 2012-07-01 09:00:29Z tuexen $");
*/

#define OFP_ICMP_ECHO_HEADER_LEN 8

/*
 * ICMP routines: error generation, receive packet processing, and
 * routines to turnaround packets back to the originator, and
 * host table maintenance routines.
 */
/*
static VNET_DEFINE(int, icmplim) = 200;
#define	V_icmplim			VNET(icmplim)
SYSCTL_VNET_INT(_net_inet_icmp, ICMPCTL_ICMPLIM, icmplim, CTLFLAG_RW,
	&VNET_NAME(icmplim), 0,
	"Maximum number of ICMP responses per second");

static VNET_DEFINE(int, icmplim_output) = 1;
#define	V_icmplim_output		VNET(icmplim_output)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, icmplim_output, CTLFLAG_RW,
	&VNET_NAME(icmplim_output), 0,
	"Enable rate limiting of ICMP responses");

#ifdef INET
VNET_DEFINE(struct icmpstat, icmpstat);
SYSCTL_VNET_STRUCT(_net_inet_icmp, ICMPCTL_STATS, stats, CTLFLAG_RW,
	&VNET_NAME(icmpstat), icmpstat, "");

static VNET_DEFINE(int, icmpmaskrepl) = 0;
#define	V_icmpmaskrepl			VNET(icmpmaskrepl)
SYSCTL_VNET_INT(_net_inet_icmp, ICMPCTL_MASKREPL, maskrepl, CTLFLAG_RW,
	&VNET_NAME(icmpmaskrepl), 0,
	"Reply to ICMP Address Mask Request packets.");

static VNET_DEFINE(u_int, icmpmaskfake) = 0;
#define	V_icmpmaskfake			VNET(icmpmaskfake)
SYSCTL_VNET_UINT(_net_inet_icmp, OID_AUTO, maskfake, CTLFLAG_RW,
	&VNET_NAME(icmpmaskfake), 0,
	"Fake reply to ICMP Address Mask Request packets.");

static VNET_DEFINE(int, drop_redirect) = 0;
#define	V_drop_redirect			VNET(drop_redirect)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, drop_redirect, CTLFLAG_RW,
	&VNET_NAME(drop_redirect), 0,
	"Ignore ICMP redirects");

static VNET_DEFINE(int, log_redirect) = 0;
#define	V_log_redirect			VNET(log_redirect)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, log_redirect, CTLFLAG_RW,
	&VNET_NAME(log_redirect), 0,
	"Log ICMP redirects to the console");

static VNET_DEFINE(char, reply_src[IFNAMSIZ]);
#define	V_reply_src			VNET(reply_src)
SYSCTL_VNET_STRING(_net_inet_icmp, OID_AUTO, reply_src, CTLFLAG_RW,
	&VNET_NAME(reply_src), IFNAMSIZ,
	"icmp reply source for non-local packets.");

static VNET_DEFINE(int, icmp_rfi) = 0;
#define	V_icmp_rfi			VNET(icmp_rfi)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, reply_from_interface, CTLFLAG_RW,
	&VNET_NAME(icmp_rfi), 0,
	"ICMP reply from incoming interface for non-local packets");

static VNET_DEFINE(int, icmp_quotelen) = 8;
#define	V_icmp_quotelen			VNET(icmp_quotelen)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, quotelen, CTLFLAG_RW,
	&VNET_NAME(icmp_quotelen), 0,
	"Number of bytes from original packet to quote in ICMP reply");
*/
/*
 * ICMP broadcast echo sysctl
 */
/*
static VNET_DEFINE(int, icmpbmcastecho) = 0;
#define	V_icmpbmcastecho		VNET(icmpbmcastecho)
SYSCTL_VNET_INT(_net_inet_icmp, OID_AUTO, bmcastecho, CTLFLAG_RW,
	&VNET_NAME(icmpbmcastecho), 0,
	"");
*/

#ifdef ICMPPRINTFS
int	icmpprintfs = 0;
#endif

static enum ofp_return_code icmp_reflect(odp_packet_t pkt);
static void	icmp_send(odp_packet_t pkt, struct ofp_nh_entry *nh);

static enum ofp_return_code
icmp_socket_input(odp_packet_t pkt, struct ofp_ip *ip, struct ofp_icmp *icp);

extern	struct protosw inetsw[];

/*
 * Return milliseconds since 00:00 GMT in network format.
 */
static uint32_t
iptime(void)
{
	struct timeval tv;
	uint32_t t;
	gettimeofday(&tv, NULL);

	t = (tv.tv_sec % (24*60*60)) * 1000 + tv.tv_usec / 1000;
	return (odp_cpu_to_be_32(t));
}



/*
 * Kernel module interface for updating icmpstat.  The argument is an index
 * into icmpstat treated as an array of u_long.  While this encodes the
 * general layout of icmpstat into the caller, it doesn't encode its
 * location, so that future changes to add, for example, per-CPU stats
 * support won't cause binary compatibility problems for kernel modules.
 */
/*
void
kmod_icmpstat_inc(int statnum)
{

	(*((u_long *)&V_icmpstat + statnum))++;
}
*/

/*
 * Generate an error packet of type error
 * in response to bad packet ip.
 */
enum ofp_return_code
ofp_icmp_error(odp_packet_t pkt_in, int type, int code, uint32_t dest, int mtu)
{
	register struct ofp_ip *ip_in = (struct ofp_ip *)odp_packet_l3_ptr(pkt_in, NULL);
	register unsigned ip_hlen = ip_in->ip_hl << 2;
	/* ip header + icmp type+code+checksum(4B) + ip addr(4B) + ip header + 8B of original data */
	const uint16_t icmp_len = (ip_hlen * 2) + 16;
	ip_in->ip_sum = 0;
	ip_in->ip_sum = ofp_cksum_iph(ip_in, ip_in->ip_hl);

	if ((uint16_t)type > OFP_ICMP_MAXTYPE)
		OFP_ERR("Illegal ICMP type: %d", type);

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		OFP_DBG("icmp_error(%p, %x, %d)", oip, type, code);
#endif
/*	if (type != ICMP_REDIRECT)
		ICMPSTAT_INC(icps_error);*/

	/*
	 * Don't send error:
	 *  if the original packet was encrypted.
	 *  if not the first fragment of message.
	 *  in response to a multicast or broadcast packet.
	 *  if the old packet protocol was an ICMP error message.
	 */

	if ((odp_be_to_cpu_16(ip_in->ip_off) & OFP_IP_OFFMASK))
		goto freeit;
/*	if (n->m_flags & (M_BCAST|M_MCAST))
		goto freeit;*/
	if (ip_in->ip_p == OFP_IPPROTO_ICMP && type != OFP_ICMP_REDIRECT &&
		odp_packet_len(pkt_in) >= ip_hlen + OFP_ICMP_MINLEN &&
		!OFP_ICMP_INFOTYPE(((struct ofp_icmp *)
			((uintptr_t)ip_in + ip_hlen))->icmp_type)) {
		/*ICMPSTAT_INC(icps_oldicmp);*/
		goto freeit;
	}
	/*
	 * Calculate length to quote from original packet and
	 * prevent the ICMP mbuf from overflowing.
	 * Unfortunatly this is non-trivial since ip_forward()
	 * sends us truncated packets.
	 */
/*	if (oip->ip_p == IPPROTO_TCP) {
		struct tcphdr *th;
		int tcphlen;

		if (oiphlen + sizeof(struct tcphdr) > n->m_len &&
		    n->m_next == NULL)
			goto stdreply;
		if (n->m_len < oiphlen + sizeof(struct tcphdr) &&
		    ((n = m_pullup(n, oiphlen + sizeof(struct tcphdr))) == NULL))
			goto freeit;
		th = (struct tcphdr *)((caddr_t)oip + oiphlen);
		tcphlen = th->th_off << 2;
		if (tcphlen < sizeof(struct tcphdr))
			goto freeit;
		if (oip->ip_len < oiphlen + tcphlen)
			goto freeit;
		if (oiphlen + tcphlen > n->m_len && n->m_next == NULL)
			goto stdreply;
		if (n->m_len < oiphlen + tcphlen &&
		    ((n = m_pullup(n, oiphlen + tcphlen)) == NULL))
			goto freeit;
		icmpelen = max(tcphlen, min(V_icmp_quotelen, oip->ip_len - oiphlen));
	} else
stdreply:	icmpelen = max(8, min(V_icmp_quotelen, ip_in->ip_len - ip_hlen));
#ifdef MAC
	mac_netinet_icmp_reply(n, m);
#endif
*/
	odp_packet_t pkt = ofp_packet_alloc_from_pool(odp_packet_pool(pkt_in),
				icmp_len + odp_packet_l3_offset(pkt_in) -
				odp_packet_l2_offset(pkt_in));
	if (pkt == ODP_PACKET_INVALID)
		goto freeit;
	/*TODO Sometimes above odp_packet_alloc will invalidate the pkt_in*/
	if (odp_packet_l3_ptr(pkt_in, NULL) == NULL) {
		odp_packet_free(pkt);
		goto freeit;
	}

	odp_packet_l2_offset_set(pkt, odp_packet_l2_offset(pkt_in));
	odp_packet_l3_offset_set(pkt, odp_packet_l3_offset(pkt_in));

	memcpy(odp_packet_l3_ptr(pkt, NULL),
		odp_packet_l3_ptr(pkt_in, NULL),
		icmp_len);

	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	struct ofp_icmp *icp = (struct ofp_icmp *)((uint8_t *)ip + ip_hlen);
	/*
	 * Copy the quotation into ICMP message and
	 * convert quoted IP header back to network representation.
	 */
	memcpy(&icp->ofp_icmp_ip, ip_in, ip_hlen);
	memcpy((void *)((uintptr_t)(&icp->ofp_icmp_ip) + ip_hlen),
		(void *)((uintptr_t)ip_in + ip_hlen),
		(8 > (ip_in->ip_len - ip_hlen)) ? (ip_in->ip_len - ip_hlen) :8);

	icp->icmp_type = type;

	if (type == OFP_ICMP_REDIRECT)
		icp->ofp_icmp_gwaddr.s_addr = dest;
	else {
		icp->ofp_icmp_void = 0;
		/*
		 * The following assignments assume an overlay with the
		 * just zeroed icmp_void field.
		 */
		if (type == OFP_ICMP_PARAMPROB) {
			icp->ofp_icmp_pptr = code;
			code = 0;
		} else if (type == OFP_ICMP_UNREACH &&
			code == OFP_ICMP_UNREACH_NEEDFRAG && mtu) {
			icp->ofp_icmp_nextmtu = odp_cpu_to_be_16(mtu);
		}
	}
	icp->icmp_code = code;

	ip->ip_len = odp_cpu_to_be_16(icmp_len);
	ip->ip_v = OFP_IPVERSION;
	ip->ip_p = OFP_IPPROTO_ICMP;
	ip->ip_tos = 0;

	odp_packet_user_ptr_set(pkt, odp_packet_user_ptr(pkt_in));

	return icmp_reflect(pkt);
freeit:
	return OFP_PKT_DROP;
}

/*
 * Process a received ICMP message.
 */
enum ofp_return_code
ofp_icmp_input(odp_packet_t *pkt, int off)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(*pkt, NULL);
	struct ofp_icmp *icp = (struct ofp_icmp *)((uint8_t *)ip + off);
	const int icmplen = odp_be_to_cpu_16(ip->ip_len);

	if (ofp_cksum(*pkt, odp_packet_l3_offset(*pkt) + off, icmplen - (ip->ip_hl << 2)))
		return OFP_PKT_DROP;

	return _ofp_icmp_input(*pkt, ip, icp, icmp_reflect);
}

static enum ofp_return_code
icmp_deliver(struct ofp_icmp *icp, int icmplen, int code)
{
	struct ofp_sockaddr_in icmpsrc;
	pr_ctlinput_t *ctlfunc;

	bzero(&icmpsrc, sizeof(icmpsrc));
	icmpsrc.sin_len = sizeof(struct ofp_sockaddr_in);
	icmpsrc.sin_family = OFP_AF_INET;

	/*
	 * Problem with datagram; advise higher level routines.
	 */
	if (((unsigned int)icmplen) < OFP_ICMP_ADVLENMIN || icmplen < OFP_ICMP_ADVLEN(icp) ||
	    icp->ofp_icmp_ip.ip_hl < (sizeof(struct ofp_ip) >> 2)) {
		return OFP_PKT_DROP;
	}

	icp->ofp_icmp_ip.ip_len = odp_be_to_cpu_16(icp->ofp_icmp_ip.ip_len);

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		OFP_DBG("deliver to protocol %d", icp->icmp_ip.ip_p);
#endif

	icmpsrc.sin_addr = icp->ofp_icmp_ip.ip_dst;
	/*
	 * XXX if the packet contains [IPv4 AH TCP], we can't make a
	 * notification to TCP layer.
	 */
	ctlfunc = ofp_inetsw[ofp_ip_protox[icp->ofp_icmp_ip.ip_p]].pr_ctlinput;

	if (ctlfunc)
		(*ctlfunc)(code, (struct ofp_sockaddr *)&icmpsrc,
			   (void *)&icp->ofp_icmp_ip);

	return OFP_PKT_DROP;
}

static enum ofp_return_code
icmp_destination_unreachable(struct ofp_icmp *icp, int icmplen)
{
	switch (icp->icmp_code) {
	case OFP_ICMP_UNREACH_NET:
	case OFP_ICMP_UNREACH_HOST:
	case OFP_ICMP_UNREACH_SRCFAIL:
	case OFP_ICMP_UNREACH_NET_UNKNOWN:
	case OFP_ICMP_UNREACH_HOST_UNKNOWN:
	case OFP_ICMP_UNREACH_ISOLATED:
	case OFP_ICMP_UNREACH_TOSNET:
	case OFP_ICMP_UNREACH_TOSHOST:
	case OFP_ICMP_UNREACH_HOST_PRECEDENCE:
	case OFP_ICMP_UNREACH_PRECEDENCE_CUTOFF:
		return icmp_deliver(icp, icmplen, OFP_PRC_UNREACH_NET);

	case OFP_ICMP_UNREACH_NEEDFRAG:
		return icmp_deliver(icp, icmplen, OFP_PRC_MSGSIZE);

	/*
	 * RFC 1122, Sections 3.2.2.1 and 4.2.3.9.
	 * Treat subcodes 2,3 as immediate RST
	 */
	case OFP_ICMP_UNREACH_PROTOCOL:
	case OFP_ICMP_UNREACH_PORT:
		return icmp_deliver(icp, icmplen, OFP_PRC_UNREACH_PORT);

	case OFP_ICMP_UNREACH_NET_PROHIB:
	case OFP_ICMP_UNREACH_HOST_PROHIB:
	case OFP_ICMP_UNREACH_FILTER_PROHIB:
		return icmp_deliver(icp, icmplen, OFP_PRC_UNREACH_ADMIN_PROHIB);

	default:
		break;
    }

    return OFP_PKT_DROP;
}

static enum ofp_return_code
icmp_time_exceeded(struct ofp_icmp *icp, int icmplen)
{
	if (icp->icmp_code > 1)
		return OFP_PKT_DROP;

	return icmp_deliver(icp, icmplen, icp->icmp_code + OFP_PRC_TIMXCEED_INTRANS);
}

static enum ofp_return_code
icmp_bad_ip_header(struct ofp_icmp *icp, int icmplen)
{
	if (icp->icmp_code > 1)
		return OFP_PKT_DROP;

	return icmp_deliver(icp, icmplen, OFP_PRC_PARAMPROB);
}

static enum ofp_return_code
icmp_packet_lost(struct ofp_icmp *icp, int icmplen)
{
	if (icp->icmp_code)
		return OFP_PKT_DROP;

	return icmp_deliver(icp, icmplen, OFP_PRC_QUENCH);
}

static enum ofp_return_code
icmp_echo(odp_packet_t pkt, struct ofp_icmp *icp,
	  enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
	icp->icmp_type = OFP_ICMP_ECHOREPLY;
	return reflect(pkt);
}

static enum ofp_return_code
icmp_timestamp_request(odp_packet_t pkt, struct ofp_icmp *icp, int icmplen,
		       enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
	if ((unsigned int)icmplen < OFP_ICMP_TSLEN)
		return OFP_PKT_DROP;

	icp->icmp_type = OFP_ICMP_TSTAMPREPLY;
	icp->ofp_icmp_rtime = iptime();
	icp->ofp_icmp_ttime = icp->ofp_icmp_rtime;      /* bogus, do later! */
	return reflect(pkt);
}

static enum ofp_return_code
icmp_address_mask_request(odp_packet_t pkt,
			  enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
/*TODO  if (V_icmpmaskrepl == 0)*/
		return OFP_PKT_DROP;

	return reflect(pkt);
}

static enum ofp_return_code
icmp_shorter_route(struct ofp_ip *ip, struct ofp_icmp *icp)
{
	/*if (V_log_redirect)*/ {
#if defined(OFP_DEBUG)
		u_long src, dst, gw;

		src = odp_be_to_cpu_32(ip->ip_src.s_addr);
		dst = odp_be_to_cpu_32(icp->ofp_icmp_ip.ip_dst.s_addr);
		gw = odp_be_to_cpu_32(icp->ofp_icmp_gwaddr.s_addr);
		OFP_DBG("icmp redirect from %d.%d.%d.%d: "
		       "%d.%d.%d.%d => %d.%d.%d.%d",
		       (int)(src >> 24), (int)((src >> 16) & 0xff),
		       (int)((src >> 8) & 0xff), (int)(src & 0xff),
		       (int)(dst >> 24), (int)((dst >> 16) & 0xff),
		       (int)((dst >> 8) & 0xff), (int)(dst & 0xff),
		       (int)(gw >> 24), (int)((gw >> 16) & 0xff),
		       (int)((gw >> 8) & 0xff), (int)(gw & 0xff));
#else
		(void)ip;
		(void)icp;
#endif
	}
	/*
	 * RFC1812 says we must ignore ICMP redirects if we
	 * are acting as router.
	 */
/*TODO  if (V_drop_redirect || V_ipforwarding) */
		return OFP_PKT_DROP;
	/*
	 * Short circuit routing redirects to force
	 * immediate change in the kernel's routing
	 * tables.  The message is also handed to anyone
	 * listening on a raw socket (e.g. the routing
	 * daemon for use in updating its tables).
	 */
}

enum ofp_return_code
_ofp_icmp_input(odp_packet_t pkt, struct ofp_ip *ip, struct ofp_icmp *icp,
		enum ofp_return_code (*reflect)(odp_packet_t pkt))
{
	const int icmplen = odp_be_to_cpu_16(ip->ip_len);

#ifdef PROMISCUOUS_INET
	/* XXX ICMP plumbing is currently incomplete for promiscuous mode interfaces not in fib 0 */
	if ((m->m_pkthdr.rcvif->if_flags & IFF_PROMISCINET) &&
	    (M_GETFIB(m) > 0))
		return OFP_PKT_DROP;
#endif

	/*
	 * Locate icmp structure in mbuf, and check
	 * that not corrupted and of at least minimum length.
	 */
#ifdef ICMPPRINTFS
	if (icmpprintfs) {
		char buf[4 * sizeof "123"];
		strcpy(buf, inet_ntoa(ip->ip_src));
		OFP_DBG("icmp_input from %s to %s, len %d",
		       buf, inet_ntoa(ip->ip_dst), icmplen);
	}
#endif

	if (icmplen < OFP_ICMP_MINLEN)
		return OFP_PKT_DROP;

#ifdef ICMPPRINTFS
	if (icmpprintfs)
		OFP_DBG("icmp_input, type %d code %d", icp->icmp_type,
		    icp->icmp_code);
#endif
	/*
	 * Message type specific processing.
	 */
/*TODO ICMP stats
	ICMPSTAT_INC(icps_inhist[icp->icmp_type]);*/
	switch (icp->icmp_type) {

	case OFP_ICMP_UNREACH:
		return icmp_destination_unreachable(icp, icmplen);

	case OFP_ICMP_TIMXCEED:
		return icmp_time_exceeded(icp, icmplen);

	case OFP_ICMP_PARAMPROB:
		return icmp_bad_ip_header(icp, icmplen);

	case OFP_ICMP_SOURCEQUENCH:
		return icmp_packet_lost(icp, icmplen);

	case OFP_ICMP_ECHO:
		return icmp_echo(pkt, icp, reflect);

	case OFP_ICMP_ECHOREPLY:
		return icmp_socket_input(pkt, ip, icp);

	case OFP_ICMP_TSTAMP:
		return icmp_timestamp_request(pkt, icp, icmplen, reflect);

	case OFP_ICMP_MASKREQ:
		return icmp_address_mask_request(pkt, reflect);

	case OFP_ICMP_REDIRECT:
		return icmp_shorter_route(ip, icp);

	default:
		break;
	}

	/*
	 * Anything we didn't process is forwarded to slow path.
	 */
	return OFP_PKT_CONTINUE;
}

/*
 * Reflect the ip packet back to the source
 */
static enum ofp_return_code
icmp_reflect(odp_packet_t pkt)
{
	struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	struct ofp_in_addr t;
	struct ofp_nh_entry *nh = NULL;
	struct ofp_nh_entry *nh_src = NULL;
	struct ofp_ifnet *dev_out, *ifp = odp_packet_user_ptr(pkt);
	int optlen = (ip->ip_hl << 2) - sizeof(*ip);
	uint32_t flags = 0;

/*	if (IN_MULTICAST(odp_be_to_cpu_32(ip->ip_src.s_addr)) ||
	    IN_EXPERIMENTAL(odp_be_to_cpu_32(ip->ip_src.s_addr)) ||
	    IN_ZERONET(odp_be_to_cpu_32(ip->ip_src.s_addr)) ) {
		MPSTAT_INC(icps_badaddr);
		goto done;
* Ip_output() will check for broadcast
	}
*/
	if (ifp == NULL)
		goto drop;

	t = ip->ip_dst;
	ip->ip_dst = ip->ip_src;

	/*
	 * Source selection for ICMP replies:
	 *
	 * If the incoming packet was addressed directly to one of our
	 * own addresses, use dst as the src for the reply.
	 */
	nh_src = ofp_get_next_hop(ifp->vrf, t.s_addr, &flags);
	if (nh_src && (nh_src->flags & OFP_RTF_LOCAL))
		goto match;

	/*
	 * If the incoming packet was addressed to one of our broadcast
	 * addresses, use the first non-broadcast address which corresponds
	 * to the incoming interface.
	 */
/*	ifp = m->m_pkthdr.rcvif;
	if (ifp != NULL && ifp->if_flags & IFF_BROADCAST) {
		IF_ADDR_RLOCK(ifp);
		OFP_TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			ia = ifatoia(ifa);
			if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr ==
			    t.s_addr) {
				t = IA_SIN(ia)->sin_addr;
				IF_ADDR_RUNLOCK(ifp);
				goto match;
			}
		}
		IF_ADDR_RUNLOCK(ifp);
	}
*/
	/*
	 * If the packet was transiting through us, use the address of
	 * the interface the packet came through in.  If that interface
	 * doesn't have a suitable IP address, the normal selection
	 * criteria apply.
	 */
	t.s_addr = 0;
	if (1 /*V_icmp_rfi*/)
		t.s_addr = ifp->ip_addr_info[0].ip_addr;
	/*
	 * If the packet was transiting through us, use the address of
	 * the interface that is the closest to the packet source.
	 * When we don't have a route back to the packet source, stop here
	 * and drop the packet.
	 */
	nh = ofp_get_next_hop(ifp->vrf, ip->ip_dst.s_addr, &flags);
	if (nh == NULL) {
/*		ICMPSTAT_INC(icps_noroute);*/
		if (t.s_addr)
			goto match;
		else
			goto drop;

	}
	dev_out = ofp_get_ifnet(nh->port, nh->vlan, 0);
	t.s_addr = dev_out->ip_addr_info[0].ip_addr;
match:
#ifdef MAC
	mac_netinet_icmp_replyinplace(m);
#endif
	ip->ip_src = t;
	ip->ip_ttl = 64; /*default ttl, from RFC 1340*/

	if (optlen > 0) {
		/*TODO Uncomment and adapt this code once option processing has been implemented.
		register u_char *cp;
		int opt, cnt;
		u_int len;
		 * Retrieve any source routing from the incoming packet;
		 * add on any record-route or timestamp options.
		cp = (u_char *) (ip + 1);
		if ((opts = ip_srcroute(m)) == 0 &&
		    (opts = m_gethdr(M_DONTWAIT, MT_DATA))) {
			opts->m_len = sizeof(struct in_addr);
			mtod(opts, struct in_addr *)->s_addr = 0;
		}
		if (opts) {
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    OFP_DBG("icmp_reflect optlen %d rt %d => ",
				optlen, opts->m_len);
#endif
		    for (cnt = optlen; cnt > 0; cnt -= len, cp += len) {
			    opt = cp[IPOPT_OPTVAL];
			    if (opt == IPOPT_EOL)
				    break;
			    if (opt == IPOPT_NOP)
				    len = 1;
			    else {
				    if (cnt < IPOPT_OLEN + sizeof(*cp))
					    break;
				    len = cp[IPOPT_OLEN];
				    if (len < IPOPT_OLEN + sizeof(*cp) ||
					len > cnt)
					    break;
			    }
			     * Should check for overflow, but it "can't happen"
			    if (opt == IPOPT_RR || opt == IPOPT_TS ||
				opt == IPOPT_SECURITY) {
				    bcopy((caddr_t)cp,
					mtod(opts, caddr_t) + opts->m_len, len);
				    opts->m_len += len;
			    }
		    }
		    * Terminate & pad, if necessary
		    cnt = opts->m_len % 4;
		    if (cnt) {
			    for (; cnt < 4; cnt++) {
				    *(mtod(opts, caddr_t) + opts->m_len) =
					IPOPT_EOL;
				    opts->m_len++;
			    }
		    }
#ifdef ICMPPRINTFS
		    if (icmpprintfs)
			    OFP_DBG("%d", opts->m_len);
#endif
		}
		 * Now strip out original options by copying rest of first
		 * mbuf's data back, and adjust the IP length.
		ip->ip_len -= optlen;
		ip->ip_v = IPVERSION;
		ip->ip_hl = 5;
		m->m_len -= optlen;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len -= optlen;
		optlen += sizeof(struct ip);
		bcopy((caddr_t)ip + optlen, (caddr_t)(ip + 1),
			 (unsigned)(m->m_len - sizeof(struct ip)));
		*/

		/*
		 * Since we don't have IP option processing (yet),
		 * it's best to just remove all options.
		 */
		uint32_t optpos = odp_packet_l3_offset(pkt) + sizeof(struct ofp_ip);

		/* Move packet data back, overwriting IP options. */
		if (odp_packet_move_data(pkt, optpos, optpos + optlen,
					 odp_packet_len(pkt) - (optpos + optlen)))
			goto drop;
		if (!odp_packet_pull_tail(pkt, optlen))
			goto drop;

		ip->ip_v = OFP_IPVERSION;
		ip->ip_hl = 5;
		uint16_t ip_len = odp_be_to_cpu_16(ip->ip_len);
		ip_len -= optlen;
		ip->ip_len = odp_cpu_to_be_16(ip_len);
	}

	icmp_send(pkt, nh/*, opts*/);
	return OFP_PKT_PROCESSED;
drop:
	return OFP_PKT_DROP;
}

/*
 * Send an icmp packet back to the ip level,
 * after supplying a checksum.
 */
static void
icmp_send(odp_packet_t pkt, struct ofp_nh_entry *nh)
{
	register struct ofp_ip *ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	register uint16_t hlen = ip->ip_hl << 2;
	register struct ofp_icmp *icp = (struct ofp_icmp *)((uint8_t *)ip + hlen);

	icp->icmp_cksum = 0;
	icp->icmp_cksum = ofp_cksum(pkt, odp_packet_l3_offset(pkt) + hlen,
				      odp_be_to_cpu_16(ip->ip_len) - hlen);

#ifdef ICMPPRINTFS
	if (icmpprintfs) {
		char buf[4 * sizeof "123"];
		strcpy(buf, inet_ntoa(ip->ip_dst));
		OFP_DBG("icmp_send dst %s src %s",
		       buf, inet_ntoa(ip->ip_src));
	}
#endif
	(void) ofp_ip_output(pkt, nh);
}

static int
icmp_inpcb_init(void *mem, int size, int flags)
{
	struct inpcb *inp;

	(void)size;
	(void)flags;

	inp = mem;
	INP_LOCK_INIT(inp, "inp", "icmpinp");
	return 0;
}

void ofp_icmp_init(void)
{
	INP_INFO_LOCK_INIT(&V_icmbinfo, 0);

	ofp_in_pcbinfo_init("icmp",
			    &V_icmbinfo, &V_icmb,
			    V_icmp_hashtbl, V_icmp_hashtbl_size,
			    V_icmp_porthashtbl, V_icmp_porthashtbl_size,
			    icmp_inpcb_init, NULL, 0,
			    (uint32_t)global_param->icmp.pcb_icmp_max);
}

void ofp_icmp_destroy(void)
{
	struct inpcb *inp, *inp_temp;

	OFP_LIST_FOREACH_SAFE(inp, V_icmbinfo.ipi_listhead, inp_list,
			      inp_temp) {
		if (inp->inp_socket) {
			ofp_sbdestroy(&inp->inp_socket->so_snd,
				      inp->inp_socket);
			ofp_sbdestroy(&inp->inp_socket->so_rcv,
				      inp->inp_socket);
		}

		uma_zfree(V_icmbinfo.ipi_zone, inp);
	}

	ofp_in_pcbinfo_destroy(&V_icmbinfo);
	uma_zdestroy(V_icmbinfo.ipi_zone);
}

static int
icmp_attach(struct socket *so, int proto, struct thread *td)
{
	struct inpcb *inp;
	int error;

	(void)proto;
	(void)td;

	inp = sotoinpcb(so);
	KASSERT(inp == NULL, ("%s: inp != NULL", __func__));

	/* HJo: Constant space reserved.
	error = ofp_soreserve(so, V_udp_sendspace, V_udp_recvspace);
	if (error)
		return (error);
	*/

	INP_INFO_WLOCK(&V_icmbinfo);

	error = ofp_in_pcballoc(so, &V_icmbinfo);
	if (error) {
		INP_INFO_WUNLOCK(&V_icmbinfo);
		return error;
	}

	inp = sotoinpcb(so);
	inp->inp_vflag |= INP_IPV4;
	inp->inp_ip_ttl = V_ip_defttl;

	/* HJo: Replaced by static allocation.
	error = udp_newudpcb(inp);
	if (error) {
		ofp_in_pcbdetach(inp);
		ofp_in_pcbfree(inp);
		INP_INFO_WUNLOCK(&V_udbinfo);
		return (error);
	}
	*/

	inp->ppcb_space.icmp_ppcb.u_seq = 0;
	inp->ppcb_space.icmp_ppcb.send_timestamp = 0;
	inp->inp_ppcb = &inp->ppcb_space.icmp_ppcb;

	INP_WUNLOCK(inp);
	INP_INFO_WUNLOCK(&V_icmbinfo);
	return 0;
}

static void
icmp_detach(struct socket *so)
{
	struct inpcb *inp;
	struct icmpcb *icmpp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("%s: inp == NULL", __func__));
	KASSERT(inp->inp_faddr.s_addr == OFP_INADDR_ANY,
		("%s: not disconnected", __func__));

	INP_INFO_WLOCK(&V_icmbinfo);
	INP_WLOCK(inp);
	icmpp = intoicmpcb(inp);
	KASSERT(icmpp != NULL, ("%s: icmpp == NULL", __func__));
	inp->inp_ppcb = NULL;
	ofp_in_pcbdetach(inp);
	ofp_in_pcbfree(inp);
	INP_INFO_WUNLOCK(&V_icmbinfo);
}

static void
icmp_close(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("%s: inp == NULL", __func__));
	INP_WLOCK(inp);
	if (inp->inp_faddr.s_addr != OFP_INADDR_ANY) {
		INP_HASH_WLOCK(&V_icmbinfo);
		ofp_in_pcbdisconnect(inp);
		inp->inp_laddr.s_addr = OFP_INADDR_ANY;
		INP_HASH_WUNLOCK(&V_icmbinfo);
		ofp_soisdisconnected(so);
	}
	INP_WUNLOCK(inp);
}

static int
icmp_connect(struct socket *so, struct ofp_sockaddr *nam, struct thread *td)
{
	struct inpcb *inp;
	int error = 0;
	struct ofp_sockaddr_in *sin = (struct ofp_sockaddr_in *)nam;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("%s: inp == NULL", __func__));
	INP_WLOCK(inp);
	if (inp->inp_faddr.s_addr != OFP_INADDR_ANY) {
		INP_WUNLOCK(inp);
		return OFP_EISCONN;
	}

	(void)td;

	inp->inp_lport = 0;
	inp->inp_laddr.s_addr = OFP_INADDR_ANY;
	inp->inp_faddr.s_addr = sin->sin_addr.s_addr;
	inp->inp_fport = sin->sin_port;

	if (error == 0)
		ofp_soisconnected(so);
	INP_WUNLOCK(inp);
	return error;
}

static int
icmp_disconnect(struct socket *so)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	KASSERT(inp != NULL, ("%s: inp == NULL", __func__));
	INP_WLOCK(inp);
	if (inp->inp_faddr.s_addr == OFP_INADDR_ANY) {
		INP_WUNLOCK(inp);
		return OFP_ENOTCONN;
	}

	inp->inp_laddr.s_addr = OFP_INADDR_ANY;
	inp->inp_faddr.s_addr = OFP_INADDR_ANY;

	OFP_SOCK_LOCK(so);
#if 1 /* HJo: FIX */
	so->so_state &= ~SS_ISCONNECTED;		/* XXX */
#endif
	OFP_SOCK_UNLOCK(so);
	INP_WUNLOCK(inp);
	return 0;
}

static int
icmp_sosend(struct socket *so, struct ofp_sockaddr *addr, struct ofp_uio *uio,
	    odp_packet_t top, odp_packet_t control, int flags,
	    struct thread *td)
{
	int error = 0;
	struct inpcb *inp = NULL;
	struct icmpcb *icmpp = NULL;
	const uint8_t *data;
	ofp_ssize_t resid;
	odp_packet_t pkt = ODP_PACKET_INVALID;
	uint16_t pkt_len = 0;
	struct ofp_ip *ip = NULL;
	struct ofp_icmp *icp = NULL;
	ofp_in_addr_t out_addr = 0;
	uint16_t out_id = 0;

	(void)top;
	(void)control;
	(void)flags;
	(void)td;

	KASSERT(so->so_type == OFP_SOCK_RAW, ("%s: !OFP_SOCK_RAW", __func__));
	KASSERT(so->so_proto->pr_flags & PR_ATOMIC,
		("%s: !PR_ATOMIC", __func__));

	inp = sotoinpcb(so);
	icmpp = intoicmpcb(inp);

	if (uio != NULL) {
		data = uio->uio_iov->iov_base;
		resid = uio->uio_iov->iov_len;
	} else {
		data = odp_packet_data(top);
		resid = odp_packet_len(top);
	}

	if (addr) {
		out_addr = ((struct ofp_sockaddr_in *)addr)->sin_addr.s_addr;
		out_id = ((struct ofp_sockaddr_in *)addr)->sin_port;
	} else {
		out_addr = inp->inp_faddr.s_addr;
		out_id = inp->inp_fport;
	}

	if (resid < (ofp_ssize_t)(sizeof(struct ofp_icmpdata))) {
		OFP_ERR("ICMP data should be at least %ld bytes in length",
			sizeof(struct ofp_icmpdata));
		error = OFP_EINVAL;
		goto out;
	}

/*
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Code      |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Data ...
   +-+-+-+-+-
*/
	pkt_len = sizeof(struct ofp_ether_vlan_header) + sizeof(struct ofp_ip) +
		OFP_ICMP_ECHO_HEADER_LEN + resid;

	pkt = ofp_socket_packet_alloc(pkt_len);

	if (pkt == ODP_PACKET_INVALID) {
		error = OFP_ENOMEM;
		goto out;
	}

	odp_memset(odp_packet_data(pkt), 0, pkt_len);

	odp_packet_l2_offset_set(pkt, 0);
	odp_packet_l3_offset_set(pkt, sizeof(struct ofp_ether_vlan_header));

	/* Set IP */
	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);

	ip->ip_v = OFP_IPVERSION;
	ip->ip_hl = sizeof(*ip) >> 2;
	ip->ip_tos = inp->inp_ip_tos;
	ip->ip_len = odp_cpu_to_be_16(pkt_len - odp_packet_l3_offset(pkt));
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = V_ip_defttl;
	ip->ip_p = OFP_IPPROTO_ICMP;
	ip->ip_dst.s_addr = out_addr;

	/* Set ICMP */
	icp = (struct ofp_icmp *)(ip + 1);
	icp->icmp_type = OFP_ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->ofp_icmp_id = out_id;
	icp->ofp_icmp_seq = odp_cpu_to_be_16(++icmpp->u_seq);
	icmpp->send_timestamp = odp_time_local_ns();

	odp_memcpy((uint8_t *)icp + OFP_ICMP_ECHO_HEADER_LEN, data, resid);

	icmp_send(pkt, NULL);

	return 0;
out:
	if (pkt != ODP_PACKET_INVALID) {
		odp_packet_free(pkt);
		pkt = ODP_PACKET_INVALID;
	}

	return error;
}

static enum ofp_return_code
icmp_socket_input(odp_packet_t pkt, struct ofp_ip *ip, struct ofp_icmp *icp)
{
	enum ofp_return_code ret = OFP_PKT_CONTINUE;
	struct inpcb *inp = NULL;
	struct icmpcb *icmpp = NULL;
	struct inpcbhead *ipi_listhead = NULL;
	struct socket *so = NULL;
	odp_bool_t found = 0;
	struct ofp_icmpdata *icp_data = NULL;

	INP_INFO_RLOCK(&V_icmbinfo);

	ipi_listhead = V_icmbinfo.ipi_listhead;

	OFP_LIST_FOREACH(inp, ipi_listhead, inp_list) {
		INP_RLOCK(inp);

		if ((inp->inp_vflag & INP_IPV4) != 0  &&
		    inp->inp_faddr.s_addr == ip->ip_src.s_addr &&
		    inp->inp_fport == icp->ofp_icmp_id) {
			icmpp = intoicmpcb(inp);

			if (odp_be_to_cpu_16(icp->ofp_icmp_seq) != icmpp->u_seq) {
				/* Drop late packets */
				odp_packet_free(pkt);
				pkt = ODP_PACKET_INVALID;
			} else {
				/* Save time diff. between send and receive time
				in the first 8 bytes of the packet*/
				icp_data = (struct ofp_icmpdata *)((uint8_t *)icp + OFP_ICMP_ECHO_HEADER_LEN);
				icp_data->rtt = odp_time_local_ns() -
					icmpp->send_timestamp;
				icp_data->seq = icmpp->u_seq;
				icp_data->ttl = ip->ip_ttl;

				so = inp->inp_socket;

				SOCKBUF_LOCK(&so->so_rcv);
				if (ofp_sbappendaddr_locked(&so->so_rcv, pkt, ODP_PACKET_INVALID) == 0) {
					SOCKBUF_UNLOCK(&so->so_rcv);
					odp_packet_free(pkt);
					pkt = ODP_PACKET_INVALID;
				} else {
					sorwakeup_locked(so);
				}
			}

			found = 1;
			ret = OFP_PKT_PROCESSED;
		}

		INP_RUNLOCK(inp);

		if (found)
			break;
	}

	INP_INFO_RUNLOCK(&V_icmbinfo);

	return ret;
}

static int
icmp_soreceive(struct socket *so, struct ofp_sockaddr **psa,
	       struct ofp_uio *uio, odp_packet_t *mp0,
	       odp_packet_t *controlp, int *flagsp)
{
	int error = 0;
	odp_packet_t pkt;
	struct ofp_ip *ip = NULL;
	struct ofp_icmp *icp = NULL;
	uint8_t *icp_data = NULL;
	ofp_size_t icp_data_len = 0;

	(void)mp0;
	(void)controlp;
	(void)flagsp;

	if (uio->uio_iov->iov_len < sizeof(struct ofp_icmpdata)) {
		OFP_ERR("ICMP receive data buffer should be at least %ld bytes "
			"in length", sizeof(uint64_t));
		return OFP_EINVAL;
	}

	SOCKBUF_LOCK(&so->so_rcv);
	while (so->so_rcv.sb_put == so->so_rcv.sb_get) {
		error = ofp_sbwait(&so->so_rcv);
		if (error) {
			SOCKBUF_UNLOCK(&so->so_rcv);
			return error;
		}
	}

	pkt = so->so_rcv.sb_mb[so->so_rcv.sb_get];
	sbfree(&so->so_rcv, pkt);
	if (++so->so_rcv.sb_get >= SOCKBUF_LEN)
		so->so_rcv.sb_get = 0;

	SOCKBUF_UNLOCK(&so->so_rcv);

	ip = (struct ofp_ip *)odp_packet_l3_ptr(pkt, NULL);
	icp = (struct ofp_icmp *)((uint8_t *)ip + (ip->ip_hl << 2));
	icp_data = (uint8_t *)icp + OFP_ICMP_ECHO_HEADER_LEN;
	icp_data_len = odp_be_to_cpu_16(ip->ip_len) - (ip->ip_hl << 2) -
		OFP_ICMP_ECHO_HEADER_LEN;

	if (icp_data_len > uio->uio_iov->iov_len)
		icp_data_len = uio->uio_iov->iov_len;

	odp_memcpy(uio->uio_iov->iov_base, icp_data, icp_data_len);

	if (psa && *psa) {
		struct ofp_sockaddr_in *addr = (struct ofp_sockaddr_in *)*psa;

		odp_memset(addr, 0, sizeof(struct ofp_sockaddr_in));
		addr->sin_addr.s_addr = ip->ip_src.s_addr;
		addr->sin_port = icp->ofp_icmp_id;
	}

	odp_packet_free(pkt);
	uio->uio_resid -= icp_data_len;
	return 0;
}

struct pr_usrreqs ofp_icmp_usrreqs = {
	.pru_attach =		icmp_attach,
	.pru_close =		icmp_close,
	.pru_detach =		icmp_detach,
	.pru_connect =		icmp_connect,
	.pru_disconnect =	icmp_disconnect,
	.pru_sosend =		icmp_sosend,
	.pru_soreceive =	icmp_soreceive,

	.pru_accept =		ofp_pru_accept_notsupp,
	.pru_bind =		ofp_pru_bind_notsupp,
	.pru_connect2 =		ofp_pru_connect2_notsupp,
	.pru_control =		ofp_pru_control_notsupp,
	.pru_listen =		ofp_pru_listen_notsupp,
	.pru_peeraddr =		ofp_pru_peeraddr_notsupp,
	.pru_rcvd =		ofp_pru_rcvd_notsupp,
	.pru_rcvoob =		ofp_pru_rcvoob_notsupp,
	.pru_send =		ofp_pru_send_notsupp,
	.pru_sense =		ofp_pru_sense_null,
	.pru_shutdown =		ofp_pru_shutdown_notsupp,
	.pru_sockaddr =		ofp_pru_sockaddr_notsupp,
	.pru_sopoll =		ofp_pru_sopoll_notsupp,
};
