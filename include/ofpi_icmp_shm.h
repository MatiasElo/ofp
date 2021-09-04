/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __OFPI_ICMP_SHM_C__
#define __OFPI_ICMP_SHM_C__

#include "ofpi_vnet.h"
#include "ofpi_in_pcb.h"

/*
 * ICMP Shared data
 */
struct ofp_icmp_var_mem {
	VNET_DEFINE(struct inpcbhead,	icmb);
	VNET_DEFINE(struct inpcbinfo,	icmbinfo);

	VNET_DEFINE(uint32_t, hashtbl_off);
	VNET_DEFINE(uint32_t, hashtbl_size);

	VNET_DEFINE(uint32_t, porthashtbl_off);
	VNET_DEFINE(uint32_t, porthashtbl_size);
};

extern __thread struct ofp_icmp_var_mem *shm_icmp;
extern __thread struct inpcbhead *shm_icmp_hashtbl;
extern __thread struct inpcbporthead *shm_icmp_porthashtbl;

#define	V_icmb		VNET(shm_icmp->icmb)
#define	V_icmbinfo	VNET(shm_icmp->icmbinfo)

#define V_icmp_hashtbl		VNET(shm_icmp_hashtbl)
#define V_icmp_hashtbl_size	VNET(shm_icmp->hashtbl_size)

#define V_icmp_porthashtbl	VNET(shm_icmp_porthashtbl)
#define V_icmp_porthashtbl_size	VNET(shm_icmp->porthashtbl_size)

void ofp_icmp_var_init_prepare(void);
int ofp_icmp_var_init_global(void);
int ofp_icmp_var_term_global(void);
int ofp_icmp_var_init_local(void);

#endif /*__OFPI_ICMP_SHM_C__*/
