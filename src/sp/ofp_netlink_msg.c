/* Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>
#include <sys/socket.h>

#include <odp_api.h>
#include "ofpi_netlink.h"
#include "ofpi_ifnet_portconf.h"
#include "ofpi_route.h"
#include "ofpi_init.h"
#include "ofpi_log.h"
#include "ofpi_util.h"

#define ARPHRD_VXLAN 799

#ifdef NETLINK_DEBUG
static const char *rtm_msgtype_to_string(unsigned short type)
{
	switch (type) {
	case RTM_NEWLINK:
		return "RTM_NEWLINK";
	case RTM_DELLINK:
		return "RTM_DELLINK";
	case RTM_GETLINK:
		return "RTM_GETLINK";
	case RTM_SETLINK:
		return "RTM_SETLINK";
	case RTM_NEWADDR:
		return "RTM_NEWADDR";
	case RTM_DELADDR:
		return "RTM_DELADDR";
	case RTM_GETADDR:
		return "RTM_GETADDR";
	case RTM_NEWROUTE:
		return "RTM_NEWROUTE";
	case RTM_DELROUTE:
		return "RTM_DELROUTE";
	case RTM_GETROUTE:
		return "RTM_GETROUTE";
	}

	return "?Unknown?";
}
#endif

static int handle_ipv4v6_route(struct nlmsghdr *nlp, int vrf)
{
	/* string to hold content of the route */
	/* table (i.e. one entry) */
	char *dsts = NULL, *gws = NULL;
	char  dsts_str[24], gws_str[24], ifs[16], ms[24];
	uint32_t destination = 0, gateway = 0, ix = 0;

	int dst_len = 0, gw_len = 0;
	char *dst6 = NULL, *gw6 = NULL;
	struct rtmsg *rtp;
	struct rtattr *rtap;
	int rtl;

	/* get route entry header */
	rtp = (struct rtmsg *)NLMSG_DATA(nlp);

	/* TABLE_MAIN is the one that stores
	the routes needed for a forwarding router*/
	if (rtp->rtm_table != RT_TABLE_MAIN)
		return 0;
	OFP_DBG("");
	OFP_DBG("HANDLE ROUTE rtm_dst_len=%d", rtp->rtm_dst_len);

	/* init all the strings */
	bzero(dsts_str, sizeof(dsts_str));
	bzero(gws_str, sizeof(gws_str));
	bzero(ifs, sizeof(ifs));
	bzero(ms, sizeof(ms));
	/* inner loop: loop thru all the attributes of
	   one route entry */
	rtap = (struct rtattr *)RTM_RTA(rtp);
	rtl = RTM_PAYLOAD(nlp);

	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG(" -- rta_type=%d data=%p len=%ld\n",
			rtap->rta_type, RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DEBUG, RTA_DATA(rtap),
			      RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DEBUG, "\n");
#endif
		switch (rtap->rta_type) {
			/* destination IPv4 address */
		case RTA_DST:
			dst_len = RTA_PAYLOAD(rtap);

			if (dst_len == 4) {
				destination = *((uint32_t *)(RTA_DATA(rtap)));
				dsts = ofp_print_ip_addr(destination);
				OFP_DBG(" - Dest: %s", dsts);
			} else if (dst_len == 16) {
				dst6 = RTA_DATA(rtap);
				dsts  = ofp_print_ip6_addr((uint8_t *)dst6);
				OFP_DBG(" - Dest: %s", dsts);
			} else {
				OFP_DBG(" - >>> RTA_DST: len=%d <<<",
					dst_len);
			}

			break;

			/* next hop IPv4 address */
		case RTA_GATEWAY:
			gw_len = RTA_PAYLOAD(rtap);
			if (gw_len == 4) {
				gateway = *((uint32_t *)(RTA_DATA(rtap)));
				gws = ofp_print_ip_addr(gateway);
				OFP_DBG(" - Gateway: %s", gws);
			} else if (gw_len == 16) {
				gw6 = RTA_DATA(rtap);
				gws = ofp_print_ip6_addr((uint8_t *)gw6);
				OFP_DBG(" - Gateway: %s", gws);
			}

			break;
			/* unique ID associated with the network
			   interface */
		case RTA_OIF:
			ix = *((uint32_t *)RTA_DATA(rtap));
			sprintf(ifs, "%d", *((int *)RTA_DATA(rtap)));
			OFP_DBG(" - Interface: %d", ix);
			break;
		}
	}
	if (dsts == NULL)
		dsts = dsts_str;
	if (gws == NULL)
		gws = gws_str;
	sprintf(ms, "%d", rtp->rtm_dst_len);
	OFP_DBG("%s ROUTE dst=%s/%s gw=%s if=%d dst_len=%d",
		(nlp->nlmsg_type == RTM_NEWROUTE) ? "NEW" : "DEL",
		dsts, ms, gws, ix, dst_len);

	if (nlp->nlmsg_type == RTM_NEWROUTE) {
		struct ofp_ifnet *dev = ofp_get_ifnet_by_linux_ifindex(ix);

		if (dev) {
			struct ofp_route_msg msg;

			msg.vrf = vrf;
			if (dst_len == 4 || dst_len == 16) {
				msg.port = dev->port;
				msg.vlan = dev->vlan;
				if (dst_len == 4) {
					msg.type = OFP_ROUTE_ADD;
					msg.dst = destination;
					msg.masklen = rtp->rtm_dst_len;
					msg.gw = gateway;
					msg.flags = OFP_RTF_GATEWAY;
					ofp_set_route_msg(&msg);
				} else if (dst6) {
					msg.type = OFP_ROUTE6_ADD;
					memcpy(msg.dst6, dst6, dst_len);
					msg.masklen = rtp->rtm_dst_len;
					if (gw6)
						memcpy(msg.gw6, gw6, gw_len);
					else
						memset(msg.gw6, 0, 16);
					msg.flags = OFP_RTF_GATEWAY;
					ofp_set_route_msg(&msg);
				}
			} else if (dst_len == 0) {
				/* default route */
				msg.type = OFP_ROUTE_ADD;
				msg.dst = 0;
				msg.masklen = 0;
				msg.gw = gateway;
				msg.port = dev->port;
				msg.vlan = dev->vlan;
				ofp_set_route_msg(&msg);
			}
		} else {
			OFP_DBG(" - Cannot find dev ix=%d", ix);
		}
	} else {
		struct ofp_ifnet *dev = ofp_get_ifnet_by_linux_ifindex(ix);

		if (dev) {
			struct ofp_route_msg msg;

			msg.vrf = vrf;
			if (dst_len == 0) {
				/* default route */
				msg.type = OFP_ROUTE_DEL;
				msg.dst = 0;
				msg.masklen = 0;
			} else {
				msg.type = dst_len == 4 ?
					OFP_ROUTE_DEL : OFP_ROUTE6_DEL;
				if (dst6)
					memcpy(msg.dst6, dst6, dst_len);
				else
					msg.dst = destination;
				msg.masklen = rtp->rtm_dst_len;
			}
			ofp_set_route_msg(&msg);
		} else {
			OFP_DBG(" - Cannot find dev ix=%d", ix);
		}
	}
	return 0;
}

static int add_ipv4v6_addr(struct ifaddrmsg *if_entry, struct ofp_ifnet *dev,
			   unsigned char *addr, unsigned char *bcast,
			   unsigned char *laddr, int vrf)
{
	struct ofp_ifnet *dev_local;
	int masklen;
	uint32_t bcast_addr;

	if (vrf >= global_param->num_vrf) {
		OFP_DBG("VRF ID too big\n");
		return -1;
	}

	if (if_entry->ifa_family == AF_INET)	{
		if (ofp_if_type(dev) == OFP_IFT_GRE) {
			dev->ip_p2p = *((uint32_t *)addr);
			ofp_set_route_params(OFP_ROUTE_ADD, dev->vrf, dev->vlan,
					     dev->port,
					     *((uint32_t *)laddr), 32, 0,
					     OFP_RTF_LOCAL);
		} else {
			if (dev->vlan == 0)
				ofp_ifaddr_elem_add(dev);
		}
		/* dev->linux_index = if_entry->ifa_index;*/
		dev->vrf = vrf;
		masklen = if_entry->ifa_prefixlen;
		bcast_addr = bcast ? *(uint32_t *)bcast : 0;
		dev->sp_status = OFP_SP_UP;
		/* update quick access table */
		ofp_ifindex_lookup_tab_update(dev);

		if (ofp_if_type(dev) == OFP_IFT_VXLAN) {
			struct ofp_ifnet *dev_root =
				ofp_get_ifnet(dev->physport, dev->physvlan, 0);

			OFP_DBG(" - vrf=%d ip_addr=%x masklen=%d vlan=%d "
				"group=%x phys=%d/%d",
				vrf, *((uint32_t *)addr), masklen,
				dev->vlan, dev->ip_p2p,
				dev->physport, dev->physvlan);

			ofp_ifaddr_elem_del(dev);
			ofp_ifaddr_elem_add(dev);

			ofp_set_route_params(OFP_ROUTE_ADD, dev->vrf, dev->vlan,
					     OFP_IFPORT_VXLAN,
					     *((uint32_t *)addr),
					     masklen, 0, OFP_RTF_LOCAL);

			ofp_leave_multicast_group(dev);
			if (dev_root)
				ofp_join_device_to_multicast_group(dev_root,
								   dev,
								   dev->ip_p2p);
			else
				OFP_ERR(" ! VXLAN: No root device!");
		}
		if (ofp_if_type(dev) != OFP_IFT_GRE) {
			ofp_set_route_params(OFP_ROUTE_ADD, dev->vrf, dev->vlan,
					     dev->port,	*((uint32_t *)addr), 32,
					     0, OFP_RTF_LOCAL);
		}
		dev_local = ofp_get_ifnet(dev->port, dev->vlan, 0);
		if (NULL != dev_local)
			ofp_ifnet_ip_find_update_fields(dev_local,
							*((uint32_t *)addr),
							masklen, bcast_addr);
	}
#ifdef INET6
	else if (if_entry->ifa_family == AF_INET6) {
		/* dev->linux_index = if_entry->ifa_index;*/
		dev->vrf = vrf;
		if (if_entry->ifa_scope == RT_SCOPE_LINK) {
			memcpy(dev->link_local, addr, 16);
		} else {
			memcpy(dev->ip6_addr, addr, 16);
			dev->ip6_prefix = if_entry->ifa_prefixlen;
			dev->sp_status = OFP_SP_UP;
			if (dev->vlan == 0)
				ofp_ifaddr6_elem_add(dev);
		}
		/* update quick access table */
		ofp_ifindex_lookup_tab_update(dev);
	}
#endif /* INET6 */

	return 0;
}

static int del_ipv4v6_addr(struct ifaddrmsg *if_entry, struct ofp_ifnet *dev,
			   unsigned char *addr, unsigned char *laddr)
{
	(void)addr;
	(void)laddr;

	if (if_entry->ifa_family == AF_INET)	{
		uint8_t if_type = ofp_if_type(dev);
		int idx;

		OFP_DBG("DEL ADDR addr=%x laddr=%x", *((uint32_t *)addr),
			*((uint32_t *)laddr));

		idx = ofp_ifnet_ip_find(dev, *((uint32_t *)addr));
		if (-1 == idx) {
			OFP_INFO("Ip addr %s not found.\n",
				 ofp_print_ip_addr(*((uint32_t *)addr)));
		} else {
			ofp_set_route_params(OFP_ROUTE_DEL, dev->vrf,
					     dev->vlan, dev->port,
					     *((uint32_t *)addr),
					     dev->ip_addr_info[idx].masklen,
					     0 /*gw*/, 0);
			ofp_set_route_params(OFP_ROUTE_DEL, dev->vrf,
					     dev->vlan, dev->port,
					     *((uint32_t *)addr),
					     32, 0 /*gw*/, 0);
		}
		if (if_type == OFP_IFT_GRE) {
			ofp_set_route_params(OFP_ROUTE_DEL, dev->vrf,
					     dev->vlan, dev->port,
					     dev->ip_p2p,
					     dev->ip_addr_info[0].masklen,
					     0 /*gw*/, 0);
			dev->ip_p2p = 0;
		} else if (dev->vlan == 0 || if_type == OFP_IFT_VXLAN) {
			ofp_ifaddr_elem_del(dev);
		}
	}
#ifdef INET6
	else if (if_entry->ifa_family == AF_INET6) {
		uint8_t gw6[16];

		memset(gw6, 0, 16);

		ofp_set_route6_params(OFP_ROUTE6_DEL, 0 /*vrf*/, dev->vlan,
				      dev->port, dev->ip6_addr, dev->ip6_prefix,
				      gw6, 0);
		memset(dev->ip6_addr, 0, 16);

		if (dev->vlan == 0)
			ofp_ifaddr6_elem_del(dev);
	}
#endif /* INET6 */
	return 0;
}

static int handle_ipv4v6_addr(struct nlmsghdr *nlh, int vrf)
{
	/* msg RTM_NEWADDR / RTM_DELADDR contain an ifaddrmsg structure,
	optionally followed by rtattr routing attributes */
	struct ifaddrmsg *if_entry;
	char if_address[32];
	char *name = NULL;
	unsigned char *addr = NULL, *bcast = NULL, *laddr = NULL;
	struct rtattr *rtap;
	int rtl;
	struct ofp_ifnet *dev;

	memset(if_address, 0, sizeof(if_address));

	if_entry = (struct ifaddrmsg *)NLMSG_DATA(nlh);

	OFP_DBG("");
	OFP_DBG("HANDLE ADDR ix=%d", if_entry->ifa_index);

/* note : problem with IFLA_() macros : should be used for RTM_GETLINK,
RTM_NEWLINK messages, which start with ifinfomsg.
The processed msg here RTM_NEWADDR, RTM_DELADDR start with ifaddrmsg
*/
#ifdef NETLINK_DEBUG
	OFP_DBG(" -- %s: ifa_family=%d ifa_prefixlen=%d ifa_flags=0x%x"
		" ifa_scope=%d ifa_index=%d",
		rtm_msgtype_to_string(nlh->nlmsg_type),
		if_entry->ifa_family, if_entry->ifa_prefixlen,
		if_entry->ifa_flags, if_entry->ifa_scope,
		if_entry->ifa_index);
#endif
	rtap = (struct rtattr *)IFA_RTA(if_entry);
	rtl = IFA_PAYLOAD(nlh);
	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG(" -- rta_type=%d data=%p len=%ld\n", rtap->rta_type,
			RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DEBUG, RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DEBUG, "\n");
#endif
		switch (rtap->rta_type) {
		case IFA_LABEL:
			name = RTA_DATA(rtap);
			OFP_DBG(" - name=%s", name);
			break;

		case IFA_ADDRESS:
			addr = RTA_DATA(rtap);
			OFP_DBG(" - addr=%s",
				ofp_print_ip_addr(*(uint32_t *)addr));
			break;

		case IFA_LOCAL:
			if (if_entry->ifa_family == AF_INET) {
				/* For P2P Interfaces(GRE):
				   IFA_LOCAL is local address,
				   IFA_ADDR is destination address */
				laddr = RTA_DATA(rtap);
				OFP_DBG(" - laddr=%s",
					ofp_print_ip_addr(*(uint32_t *)laddr));
			}
			break;

		case IFA_BROADCAST:
			/* addr = bcast = RTA_DATA(rtap); */
			bcast = RTA_DATA(rtap);
			OFP_DBG(" - bcast=%s",
				ofp_print_ip_addr(*(uint32_t *)bcast));
			break;

		default:
			OFP_DBG(" - Unhandled rta_type=%d", rtap->rta_type);
			break;
		}
	}

	if (!addr) {
		OFP_ERR(" ! IFA_ADDRESS not present");
		return -1;
	}

	dev = ofp_get_ifnet_by_linux_ifindex(if_entry->ifa_index);
	if (!dev) {
		OFP_DBG(" ! Interface index %d not found", if_entry->ifa_index);
		return -1;
	}

	if (ofp_if_type(dev) == OFP_IFT_GRE &&
	    if_entry->ifa_family == AF_INET) {
		if (!laddr) {
			OFP_ERR(" ! IFA_LOCAL not present for GRE interface");
			return -1;
		}
	}

	if (!name)
		name = ofp_ifport_port_subport_to_sp_name(dev->port, dev->vlan);

	if (nlh->nlmsg_type == RTM_NEWADDR || nlh->nlmsg_type == RTM_DELADDR) {
		OFP_DBG(" - %s %s local=%s bcast=%s to '%s'",
			nlh->nlmsg_type == RTM_NEWADDR ? "Adding" : "Deleting",
			(if_entry->ifa_family == AF_INET) ?
				ofp_print_ip_addr(*(uint32_t *)addr) :
				(if_entry->ifa_family == AF_INET6) ?
					ofp_print_ip6_addr(addr) : "???",
			(laddr) ? ofp_print_ip_addr(*(uint32_t *)laddr) :
			"(none)",
			(bcast) ? ofp_print_ip_addr(*(uint32_t *)bcast) :
			"(none)",
			name);
	}

	if (nlh->nlmsg_type == RTM_DELADDR)
		return del_ipv4v6_addr(if_entry, dev, addr, laddr);
	else if (nlh->nlmsg_type == RTM_NEWADDR)
		return add_ipv4v6_addr(if_entry, dev, addr, bcast, laddr, vrf);

	return 0;
}

static int add_link(struct ifinfomsg *ifinfo_entry, int vlan, int link,
		    unsigned int mtu, uint32_t tun_loc, uint32_t tun_rem,
		    int vrf)
{
	struct ofp_ifnet *dev_root = NULL;
	struct ofp_ifnet *dev = NULL;
	struct ofp_ifnet key;

	OFP_DBG("ADD LINK ix=%d vlan=%d link=%d mtu=%d loc=%x rem=%x vrf=%d",
		ifinfo_entry->ifi_index, vlan, link, mtu, tun_loc, tun_rem,
		vrf);
	if (vlan != -1) {
		if (vrf >= global_param->num_vrf) {
			OFP_DBG(" - VRF ID too big.");
			return -1;
		}
		if (ifinfo_entry->ifi_type == ARPHRD_IPGRE) {
			dev_root = ofp_get_port_itf(OFP_IFPORT_GRE);
			if (ofp_get_ifnet_by_ip(tun_loc, vrf) == NULL) {
				OFP_DBG(" - Tunnel local IP not configured. "
					"Interface ignored.");
				return -1;
			}
		} else if (ifinfo_entry->ifi_type == ARPHRD_VXLAN) {
			OFP_DBG(" - VXLAN ADD LINK vlan=%d link=%d",
				vlan, link);
			dev_root = ofp_get_port_itf(OFP_IFPORT_VXLAN);
		} else {
			dev_root = ofp_get_ifnet_by_linux_ifindex(link);
		}

		if (!dev_root) {
			OFP_ERR(" ! Root interface not found: %d", link);
			return -1;
		}

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(dev_root->vlan_structs,
					&key,
					(void **)&dev)) {
			dev = ofp_vlan_alloc();
			if (!dev) {
				OFP_ERR(" ! Interface allocation failed for "
					"VLAN: %d", vlan);
				return -1;
			}

			memset(dev, 0, sizeof(struct ofp_ifnet));
			dev->port = dev_root->port;
			dev->vlan = vlan;
			dev->vrf = vrf;
			memcpy(dev->if_mac, dev_root->if_mac, 6);
			dev->if_csum_offload_flags =
				dev_root->if_csum_offload_flags;
			dev->sp_status = OFP_SP_UP;
			dev->sp_itf_mgmt = 1;
#ifdef INET6
			memcpy(dev->link_local, dev_root->link_local, 16);
#endif /* INET6 */
			OFP_DBG(" - Calling vlan_ifnet_insert: port=%d "
				"vlan=%d vrf=%d",
				dev->port, dev->vlan, dev->vrf);
			vlan_ifnet_insert(dev_root->vlan_structs, dev);
		}

		/* Update linux index in case dev was created by portconf */
		/* when linux interface index was not available yet (cli) */
		if (dev->sp_itf_mgmt && !dev->linux_index) {
			dev->linux_index = ifinfo_entry->ifi_index;
			ofp_ifindex_lookup_tab_update(dev);
		}

		if (ifinfo_entry->ifi_type == ARPHRD_VXLAN) {
			struct ofp_ifnet *dev_link =
				ofp_get_ifnet_by_linux_ifindex(link);
			OFP_DBG(" - VXLAN: vxlanrootdev=%p linkdev=%p",
				dev_root, dev_link);

			if (!dev_link) {
				OFP_ERR(" ! VXLAN: No physical device!");
			} else {
				dev->physport = dev_link->port;
				dev->physvlan = dev_link->vlan;
			}
			dev->ip_p2p = tun_rem;
			dev->pkt_pool = ofp_get_packet_pool();
			dev->if_type = OFP_IFT_VXLAN;
		} else {
			if (tun_loc)
				dev->ip_local = tun_loc;
			if (tun_rem)
				dev->ip_remote = tun_rem;
		}
	} else {
		dev = ofp_get_ifnet_by_linux_ifindex(ifinfo_entry->ifi_index);
	}

	if (mtu && dev != NULL) {
		OFP_DBG(" - Interface updated OIF=%d MTU=%u",
			ifinfo_entry->ifi_index, mtu);
		dev->if_mtu = mtu;
	}

	return 0;
}

static int del_link(struct ifinfomsg *ifinfo_entry, int vlan, int link)
{
	struct ofp_ifnet *dev_root = NULL;
	struct ofp_ifnet *dev = NULL;
	struct ofp_ifnet key;

	OFP_DBG("DEL LINK vlan=%d link=%d", vlan, link);

	if (vlan != -1) {
		if (ifinfo_entry->ifi_type == ARPHRD_IPGRE) {
			dev_root = ofp_get_port_itf(OFP_IFPORT_GRE);
		} else if (ifinfo_entry->ifi_type == ARPHRD_VXLAN) {
			dev_root = ofp_get_port_itf(OFP_IFPORT_VXLAN);
			OFP_DBG("VXLAN DEL LINK vlan=%d", vlan);
		} else {
			dev_root = ofp_get_ifnet_by_linux_ifindex(link);
		}

		if (!dev_root) {
			OFP_ERR(" ! Root interface not found: %d", link);
			return -1;
		}

		key.vlan = vlan;
		if (ofp_vlan_get_by_key(dev_root->vlan_structs,
					&key, (void **)&dev)) {
			OFP_DBG(" - Vlan %d not found", vlan);
			return 0;
		}
		if (dev->sp_itf_mgmt)
			ofp_ifindex_lookup_tab_cleanup(dev);

		vlan_ifnet_delete(dev_root->vlan_structs,
				  &key,	free_key);
		OFP_DBG(" - Interface deleted port: %d, vlan: %d, OIF=%d",
			dev_root->port, vlan, ifinfo_entry->ifi_index);
	}

	return 0;
}

static void _parse_ifla_link_info(struct rtattr *rt, int rl,
				  uint32_t *arg1, uint32_t *arg2,
				  uint32_t *arg3, uint32_t *arg4)
{
	uint32_t *tun_loc = arg1, *tun_rem = arg2;
	uint32_t *vxlan_id = arg1, *vxlan_group = arg2,
		*vxlan_port = arg3, *vxlan_link = arg4;
	struct rtattr *rtap = rt;
	int rtl = rl;
	int gre = 0, vxlan = 0;

	if (RTA_OK(rtap, rtl) && rtap->rta_type == IFLA_INFO_KIND) {
		if (strncmp(RTA_DATA(rtap), "gre", sizeof("gre")) == 0)
			gre = 1;
		else if (strncmp(RTA_DATA(rtap), "vxlan", sizeof("vxlan")) == 0)
			vxlan = 1;
	}

	if (gre || vxlan) {
		OFP_DBG(" -- IFLA_INFO_KIND: %s", (char *)RTA_DATA(rtap));
		rtap = RTA_NEXT(rtap, rtl);
	} else {
		return;
	}

	if (RTA_OK(rtap, rtl) && rtap->rta_type == IFLA_INFO_DATA) {
		OFP_DBG(" -- IFLA_INFO_DATA");
		/* next level nest */
		rtl = RTA_PAYLOAD(rtap);
		rtap = RTA_DATA(rtap);
	} else {
		return;
	}

	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG(" -- rta_type=%d data=%p len=%ld\n", rtap->rta_type,
			RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DEBUG, RTA_DATA(rtap),
			      RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DEBUG, "\n");
#endif
		if (gre) {
			switch (rtap->rta_type) {
			case IFLA_GRE_LOCAL:
				*tun_loc = *(uint32_t *)RTA_DATA(rtap);
				OFP_DBG(" -- GRE tunnel local addr = %s",
					ofp_print_ip_addr(*tun_loc));
				break;
			case IFLA_GRE_REMOTE:
				*tun_rem = *(uint32_t *)RTA_DATA(rtap);
				OFP_DBG(" -- GRE tunnel remote addr = %s",
					ofp_print_ip_addr(*tun_rem));
				break;
			default:
				break;
			}
		} else if (vxlan) {
			switch (rtap->rta_type) {
			case IFLA_VXLAN_ID:
				*vxlan_id = *(uint32_t *)RTA_DATA(rtap);
				OFP_DBG(" -- VXLAN id = %d", *vxlan_id);
				break;
			case IFLA_VXLAN_GROUP:
				*vxlan_group = *(uint32_t *)RTA_DATA(rtap);
				OFP_DBG(" -- VXLAN group = %s",
					ofp_print_ip_addr(*vxlan_group));
				break;
			case IFLA_VXLAN_PORT:
				*vxlan_port = *(uint16_t *)RTA_DATA(rtap);
				OFP_DBG(" -- VXLAN port = %d", *vxlan_port);
				break;
			case IFLA_VXLAN_LINK:
				*vxlan_link = *(uint16_t *)RTA_DATA(rtap);
				OFP_DBG(" -- VXLAN link = %d", *vxlan_link);
				break;
			default:
				break;
			}
		}
	}
}

static int handle_ifinfo(struct nlmsghdr *nlh, int vrf)
{
	struct ifinfomsg *ifinfo_entry;
	struct rtattr *rtap;
	int rtl;
	unsigned int mtu = 0; /* to match type in struct rtattr*/
	char *name = NULL;
	int link = -1;
	int vlan = -1;
	uint32_t tun_loc = 0, tun_rem = 0, arg3 = 0, arg4 = 0;
#define VXLAN_ID tun_loc
#define VXLAN_GROUP tun_rem
#define VXLAN_PORT arg3
#define VXLAN_LINK arg4
	char *vlan_txt = NULL;

	ifinfo_entry = (struct ifinfomsg *)NLMSG_DATA(nlh);

	OFP_DBG("");
	OFP_DBG("IFINFO: vrf=%d ifi_family=%u ifi_type=%u ifi_index=%d"
		" ifi_flags=0x%x ifi_change=%u", vrf,
		  ifinfo_entry->ifi_family, ifinfo_entry->ifi_type,
		  ifinfo_entry->ifi_index, ifinfo_entry->ifi_flags,
		  ifinfo_entry->ifi_change);

	rtap = (struct rtattr *)IFLA_RTA(ifinfo_entry);
	rtl = IFLA_PAYLOAD(nlh);

	for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
#ifdef NETLINK_DEBUG
		OFP_DBG(" -- rta_type=%d data=%p len=%ld\n", rtap->rta_type,
			RTA_DATA(rtap), RTA_PAYLOAD(rtap));
		ofp_print_hex(OFP_LOG_DEBUG, RTA_DATA(rtap),
			      RTA_PAYLOAD(rtap));
		OFP_LOG_NO_CTX(OFP_LOG_DEBUG, "\n");
#endif
		switch (rtap->rta_type) {
		case IFLA_MTU:
			mtu = *(unsigned int *)RTA_DATA(rtap);
			OFP_DBG(" - MTU = %u", mtu);
			break;
		case IFLA_LINK:
			link = *(unsigned int *)RTA_DATA(rtap);
			OFP_DBG(" - Link = %d", link);
			break;
		case IFLA_IFNAME:
			name = RTA_DATA(rtap);
			OFP_DBG(" - Interface name = %s", name);
			break;
		case IFLA_LINKINFO:
			OFP_DBG(" - IFLA_LINKINFO");
			_parse_ifla_link_info(RTA_DATA(rtap), RTA_PAYLOAD(rtap),
					      &tun_loc, &tun_rem, &arg3, &arg4);
			break;
		case IFLA_NET_NS_PID:
			OFP_DBG(" - IFLA_NET_NS_PID");
			break;
		case IFLA_NET_NS_FD:
			OFP_DBG(" - IFLA_NET_NS_FD");
			break;
		default:
			break;
		}
	}

	OFP_DBG(" - %s received to interface OIF %d",
		nlh->nlmsg_type == RTM_DELLINK ? "DELLINK" : "NEWLINK",
		ifinfo_entry->ifi_index);

	if (ifinfo_entry->ifi_type == ARPHRD_IPGRE) { /* GRE */
		if (!name) {
			OFP_ERR(" ! Interface name not received: %d",
				ifinfo_entry->ifi_index);
			return -1;
		}
		if (strncmp(name, OFP_GRE_IFNAME_PREFIX,
			    strlen(OFP_GRE_IFNAME_PREFIX))) {
			OFP_ERR(" ! Invalid GRE interface name: %s", name);
			return -1;
		}
		vlan = atoi(name + strlen(OFP_GRE_IFNAME_PREFIX));
		OFP_DBG(" - GRE id = %d", vlan);
	} else if (name &&
		   !strncmp(name, OFP_VXLAN_IFNAME_PREFIX,
			    strlen(OFP_VXLAN_IFNAME_PREFIX))) {
		ifinfo_entry->ifi_type = ARPHRD_VXLAN;
		vlan = VXLAN_ID;
		link = VXLAN_LINK;
		OFP_DBG(" - VXLAN id=%d group=%s port=%d link=%d", VXLAN_ID,
			ofp_print_ip_addr(VXLAN_GROUP), VXLAN_PORT, VXLAN_LINK);
	} else if ((link != -1) && (link != ifinfo_entry->ifi_index)) {/*vlan*/
		if (!name) {
			OFP_ERR(" ! Interface name not received: %d",
				ifinfo_entry->ifi_index);
			return -1;
		}
		vlan_txt = strrchr(name, '.');
		if (!vlan_txt) {
			OFP_ERR(" ! Interface vlan ID not found: %d",
				ifinfo_entry->ifi_index);
			return -1;
		}
		vlan = atoi(vlan_txt + 1);
		OFP_DBG(" - Vlan id = %d", vlan);
	}

	if (nlh->nlmsg_type == RTM_DELLINK)
		return del_link(ifinfo_entry, vlan, link);
	else if (nlh->nlmsg_type == RTM_NEWLINK)
		return add_link(ifinfo_entry, vlan, link, mtu, tun_loc,
				tun_rem, vrf);

	return 0;
}

void netlink_msg_process(int nll, char *msg_buff, int vrf)
{
	struct  nlmsghdr *nlh = (struct nlmsghdr *)msg_buff;

	for ( ; NLMSG_OK(nlh, nll); nlh = NLMSG_NEXT(nlh, nll)) {
		switch (nlh->nlmsg_type) {
		/* ARP now managed by ofp */
		case RTM_NEWNEIGH:
		case RTM_DELNEIGH:
			break;

		case RTM_DELROUTE:
		case RTM_NEWROUTE:
			handle_ipv4v6_route(nlh, vrf);
			break;

		case RTM_NEWADDR:
		case RTM_DELADDR:
			handle_ipv4v6_addr(nlh, vrf);
			break;

		case RTM_NEWLINK:
		case RTM_DELLINK:
			handle_ifinfo(nlh, vrf);
			break;

		default:
			OFP_DBG("Unknown message type, %i", nlh->nlmsg_type);
			break;
		}
	}
}

