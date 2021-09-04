/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "ofpi_icmp_shm.h"
#include "ofpi_icmp.h"
#include "ofpi_util.h"

#define SHM_NAME_ICMP_VAR "OfpIcmpVarShMem"

/* Note: HashTable of size 1 seems resonable for ICMP
*/
#define OFP_ICMP_HASHTBL_SIZE 1
#define OFP_ICMP_PORT_HASHTBL_SIZE 1

/*
 * Data per core
 */
__thread struct ofp_icmp_var_mem *shm_icmp;
__thread struct inpcbhead *shm_icmp_hashtbl;
__thread struct inpcbporthead *shm_icmp_porthashtbl;

static uint64_t get_shm_icmp_hashtbl_size(void)
{
	return OFP_ICMP_HASHTBL_SIZE *
		sizeof(struct inpcbhead);
}

static uint64_t get_shm_icmp_porthashtbl_size(void)
{
	return OFP_ICMP_PORT_HASHTBL_SIZE *
		sizeof(struct inpcbporthead);
}

static uint64_t ofp_icmp_var_get_shm_size(void)
{
	return sizeof(*shm_icmp) +
		get_shm_icmp_hashtbl_size() +
		get_shm_icmp_porthashtbl_size();
}

static int ofp_icmp_var_alloc_shared_memory(void)
{
	shm_icmp = ofp_shared_memory_alloc(SHM_NAME_ICMP_VAR,
					   ofp_icmp_var_get_shm_size());
	if (shm_icmp == NULL) {
		OFP_ERR("ofp_shared_memory_alloc failed");
		return -1;
	}

	return 0;
}

static int ofp_icmp_var_free_shared_memory(void)
{
	int rc = 0;

	if (ofp_shared_memory_free(SHM_NAME_ICMP_VAR) == -1) {
		OFP_ERR("ofp_shared_memory_free failed");
		rc = -1;
	}
	shm_icmp = NULL;
	shm_icmp_hashtbl = NULL;
	shm_icmp_porthashtbl = NULL;

	return rc;
}

static int ofp_icmp_var_lookup_shared_memory(void)
{
	shm_icmp = ofp_shared_memory_lookup(SHM_NAME_ICMP_VAR);
	if (shm_icmp == NULL) {
		OFP_ERR("ofp_shared_memory_lookup failed");
		return -1;
	}
	shm_icmp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_icmp + shm_icmp->hashtbl_off);
	shm_icmp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_icmp + shm_icmp->porthashtbl_off);

	return 0;
}

void ofp_icmp_var_init_prepare(void)
{
	ofp_shared_memory_prealloc(SHM_NAME_ICMP_VAR,
				   ofp_icmp_var_get_shm_size());
}

int ofp_icmp_var_init_global(void)
{
	HANDLE_ERROR(ofp_icmp_var_alloc_shared_memory());
	memset(shm_icmp, 0, (size_t)ofp_icmp_var_get_shm_size());

	shm_icmp->hashtbl_off = sizeof(*shm_icmp);
	shm_icmp->hashtbl_size = (uint32_t)OFP_ICMP_HASHTBL_SIZE;

	shm_icmp->porthashtbl_off = shm_icmp->hashtbl_off +
		get_shm_icmp_hashtbl_size();
	shm_icmp->porthashtbl_size = (uint32_t)OFP_ICMP_PORT_HASHTBL_SIZE;

	shm_icmp_hashtbl = (struct inpcbhead *)
		((uint8_t *)shm_icmp + shm_icmp->hashtbl_off);
	shm_icmp_porthashtbl = (struct inpcbporthead *)
		((uint8_t *)shm_icmp + shm_icmp->porthashtbl_off);

	return 0;
}

int ofp_icmp_var_term_global(void)
{
	int rc = 0;

	CHECK_ERROR(ofp_icmp_var_free_shared_memory(), rc);

	return rc;
}

int ofp_icmp_var_init_local(void)
{
	if (ofp_icmp_var_lookup_shared_memory())
		return -1;

	return 0;
}
