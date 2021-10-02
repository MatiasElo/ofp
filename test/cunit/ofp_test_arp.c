/* Copyright (c) 2014, Nokia
 * Copyright (c) 2014, ENEA Software AB
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OFP_TESTMODE_AUTO
#define OFP_TESTMODE_AUTO 1
#endif

#if defined(OFP_TESTMODE_AUTO)
#include <CUnit/Automated.h>
#else
#include <CUnit/Basic.h>
#endif

#include "ofpi.h"
#include "ofpi_arp.h"

#include "ofpi_log.h"
#include "ofp_route_arp.h"
#include "ofpi_thread_proc.h"

#include <odp_api.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define ENTRY_TIMEOUT 2

#define ALLOW_UNUSED_LOCAL(x) false ? (void)x : (void)0

static odp_atomic_u32_t still_running;
static ofp_thread_t pp_thread_handle;
int pp_thread(void *arg);

static int init_suite(void)
{
	ofp_initialize_param_t params;
	ofp_thread_param_t thread_param;

	ofp_initialize_param(&params);
	params.enable_nl_thread = 0;
	params.arp.entry_timeout = ENTRY_TIMEOUT;
	(void)ofp_initialize(&params);

	/*
	 * Start a packet processing thread to service timer events.
	 */
	odp_atomic_store_u32(&still_running, 1);

	odp_cpumask_t cpumask;
	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, 0x1);

	memset(&thread_param, 0, sizeof(thread_param));
	ofp_thread_param_init(&thread_param);
	thread_param.start = pp_thread;
	thread_param.arg = NULL;
	thread_param.thr_type = ODP_THREAD_WORKER;

	ofp_thread_create(&pp_thread_handle, 1,
			  &cpumask, &thread_param);

	return 0;
}

static int end_suite(void)
{
	odp_atomic_store_u32(&still_running, 0);

	ofp_thread_join(&pp_thread_handle, 1);

	ofp_terminate();

	return 0;
}

int pp_thread(void *arg)
{
	ALLOW_UNUSED_LOCAL(arg);

	while (odp_atomic_load_u32(&still_running)) {
		odp_event_t event;
		odp_queue_t source_queue;

		event = odp_schedule(&source_queue, ODP_SCHED_WAIT);

		if (odp_event_type(event) != ODP_EVENT_TIMEOUT) {
			OFP_ERR("Unexpected event type %d",
				odp_event_type(event));
			continue;
		}

		ofp_timer_handle(event);
	}

	return 0;
}

static void test_arp(void)
{
	struct ofp_ifnet mock_ifnet;
	struct in_addr ip;
	uint8_t mac[OFP_ETHER_ADDR_LEN] = { 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, };

	/* The buffer passed into ofp_ipv4_lookup_mac() must be 8 bytes since
	 * a 64-bit operation is currently being used to copy a MAC address.
	 */
	uint8_t mac_result[OFP_ETHER_ADDR_LEN + 2];

	memset(&mock_ifnet, 0, sizeof(mock_ifnet));
	CU_ASSERT(0 != inet_aton("1.1.1.1", &ip));

	/* Test entry insert and lookup*/
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));

	CU_ASSERT(0 == ofp_add_mac(&mock_ifnet, ip.s_addr, mac));

	memset(mac_result, 0xFF, OFP_ETHER_ADDR_LEN);
	CU_ASSERT(0 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));
	CU_ASSERT(0 == memcmp(mac, mac_result, OFP_ETHER_ADDR_LEN));

#ifndef OFP_USE_LIBCK
	/* Aging not defined in arp ck impl */
	/* Test entry is aged out. */
	CU_ASSERT(0 == ofp_add_mac(&mock_ifnet, ip.s_addr, mac));
	OFP_INFO("Inserted ARP entry");
	sleep(ENTRY_TIMEOUT*2);
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));

	/* New entry. */
	CU_ASSERT(0 == ofp_add_mac(&mock_ifnet, ip.s_addr, mac));
	OFP_INFO("Inserted ARP entry");
	/* Less than entry timeout passed, entry has not aged. */
	sleep(ENTRY_TIMEOUT/2);
	CU_ASSERT(0 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));
	/* More than entry timeout passed, entry has aged. */
	sleep(ENTRY_TIMEOUT*2);
	CU_ASSERT(-1 == ofp_ipv4_lookup_mac(ip.s_addr, mac_result, &mock_ifnet));
#endif
}

int main(void)
{
	CU_pSuite ptr_suite = NULL;
	int nr_of_failed_tests = 0;
	int nr_of_failed_suites = 0;

	/* Initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	/* add a suite to the registry */
	ptr_suite = CU_add_suite("ARP lookup", init_suite, end_suite);
	if (NULL == ptr_suite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if (NULL == CU_ADD_TEST(ptr_suite, test_arp)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

#if defined(OFP_TESTMODE_AUTO)
	CU_set_output_filename("CUnit-Arp");
	CU_automated_run_tests();
#else
	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
#endif

	nr_of_failed_tests = CU_get_number_of_tests_failed();
	nr_of_failed_suites = CU_get_number_of_suites_failed();
	CU_cleanup_registry();

	return (nr_of_failed_suites > 0 ?
		nr_of_failed_suites : nr_of_failed_tests);
}
