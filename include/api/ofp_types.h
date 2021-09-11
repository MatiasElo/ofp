/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_TYPES_H__
#define __OFP_TYPES_H__

#include <stdint.h>
#include "ofp_queue.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

/**
 * Result of processing a packet. Indicates what, if anything, the
 * caller should do with the packet.
 */
enum ofp_return_code {
	/**
	 * The caller may continue processing the packet, and should
	 * eventually free it.
	 */
	OFP_PKT_CONTINUE = 0,
	/**
	 * The packet has been processed and may already have been
	 * freed. The caller should not use the packet any further and
	 * should not free it.
	 */
	OFP_PKT_PROCESSED,
	/**
	 * The packet is dropped. The caller should free the packet.
	 */
	OFP_PKT_DROP
};

struct ofp_nh_entry {
	uint32_t flags;
	uint32_t gw;
	uint16_t port;
	uint16_t vlan;
	uint32_t arp_ent_idx;
};

struct pkt6_entry;
OFP_SLIST_HEAD(pkt6_list, pkt6_entry);

struct ofp_nh6_entry {
	uint32_t flags;
	uint8_t  gw[16];
	uint16_t port;
	uint16_t vlan;
	uint8_t  mac[6];
	struct pkt6_list pkt6_hold;
};

typedef long		__ofp_suseconds_t;	/* microseconds (signed) */
typedef unsigned int	__ofp_useconds_t;	/* microseconds (unsigned) */
typedef int		__ofp_cpuwhich_t;	/* which parameter for cpuset.*/
typedef int		__ofp_cpulevel_t;	/* level parameter for cpuset.*/
typedef int		__ofp_cpusetid_t;	/* cpuset identifier. */
typedef uint32_t	__ofp_gid_t;
typedef uint32_t	__ofp_pid_t;
typedef uint32_t	__ofp_uid_t;
typedef uint32_t	__ofp_size_t;
typedef int32_t	__ofp_ssize_t;

#ifndef OFP__GID_T_DECLARED
typedef	__ofp_gid_t		ofp_gid_t;
#define	OFP__GID_T_DECLARED
#endif /* OFP__GID_T_DECLARED */

#ifndef OFP__PID_T_DECLARED
typedef	__ofp_pid_t		ofp_pid_t;
#define	OFP__PID_T_DECLARED
#endif /* OFP__PID_T_DECLARED */

#ifndef OFP__UID_T_DECLARED
typedef	__ofp_uid_t		ofp_uid_t;
#define	OFP__UID_T_DECLARED
#endif /*OFP__UID_T_DECLARED*/

#ifndef OFP__SSIZE_T_DECLARED
typedef	__ofp_ssize_t		ofp_ssize_t;
#define	OFP__SSIZE_T_DECLARED
#endif /* OFP__SSIZE_T_DECLARED */

#ifndef OFP__SIZE_T_DECLARED
typedef	__ofp_size_t		ofp_size_t;
#define	OFP__SIZE_T_DECLARED
#endif /* OFP__SIZE_T_DECLARED */

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_TYPES_H__ */
