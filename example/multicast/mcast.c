#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "ofp.h"

#include "mcast.h"

static int mcasttest(void *arg)
{
	int fd;
	uint32_t addr_local = 0;
	uint32_t addr_mcast = 0;
	struct ofp_ip_mreq mreq;
	ofp_ifnet_t ifnet = OFP_IFNET_INVALID;
	odp_bool_t *is_running = NULL;
	char buf[1024];
	ofp_size_t buf_len = sizeof(buf);
	ofp_ssize_t len = 0;
	struct ofp_sockaddr_in addr_bind;
	struct ofp_sockaddr_in addr;
	ofp_socklen_t addr_len = 0;

	(void)arg;

	OFP_INFO("Multicast thread started\n");

	is_running = ofp_get_processing_state();
	if (is_running == NULL) {
		OFP_ERR("ofp_get_processing_state failed");
		return -1;
	}

	/* Address local */
	ifnet = ofp_ifport_ifnet_get(0, OFP_IFPORT_NET_SUBPORT_ITF);
	if (ifnet == OFP_IFNET_INVALID) {
		OFP_ERR("Interface not found.");
		return -1;
	}

	while (addr_local == 0) {
		if (ofp_ifnet_ipv4_addr_get(ifnet, OFP_IFNET_IP_TYPE_IP_ADDR,
					    &addr_local)) {
			OFP_ERR("Error: Failed to get IP address.");
			return -1;
		}
		sleep(1);
	}

	/* Address mcast */
	if (!ofp_parse_ip_addr(APP_ADDR_MCAST, &addr_mcast)) {
		OFP_ERR("Failed to get MCAST address.");
		return -1;
	}

	fd = ofp_socket(OFP_AF_INET, OFP_SOCK_DGRAM, OFP_IPPROTO_UDP);
	if (fd < 0) {
		OFP_ERR("Cannot open socket!\n");
		return -1;
	}

	/* Bind on local address */
	memset(&addr_bind, 0, sizeof(addr_bind));
	addr_bind.sin_family = OFP_AF_INET;
	addr_bind.sin_port = odp_cpu_to_be_16(APP_PORT);
	addr_bind.sin_addr.s_addr = 0;
	addr_bind.sin_len = sizeof(addr_bind);

	if (ofp_bind(fd, (struct ofp_sockaddr *)&addr_bind,
		     sizeof(struct ofp_sockaddr)) < 0) {
		OFP_ERR("Cannot bind socket (%s)!\n", ofp_strerror(ofp_errno));
		ofp_close(fd);
		return -1;
	}

	/* Mcast group membership */
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = addr_mcast;
	mreq.imr_interface.s_addr = addr_local;
	if (ofp_setsockopt(fd, OFP_IPPROTO_IP, OFP_IP_ADD_MEMBERSHIP,
			   &mreq, sizeof(mreq)) == -1) {
		OFP_ERR("ofp_setsockopt() failed: %d.", ofp_errno);
		ofp_close(fd);
		return -1;
	}

	while (*is_running) {
		len = ofp_recvfrom(fd, buf, buf_len - 1, 0,
				   (struct ofp_sockaddr *)&addr, &addr_len);
		if (len == -1) {
			OFP_ERR("Failed to rcv data(errno = %d)\n", ofp_errno);
			continue;
		}

		buf[len] = 0;
		OFP_INFO("Data (%s, len = %d) was received.\n", buf, len);

		if (addr_len != sizeof(addr)) {
			OFP_ERR("Failed to rcv source address: %d (errno = %d)",
				addr_len, ofp_errno);
			continue;
		}

		OFP_INFO("Data was received from address %s, port = %d.\n",
			 ofp_print_ip_addr(addr.sin_addr.s_addr),
			 odp_be_to_cpu_16(addr.sin_port));

		sprintf(buf, "%d bytes", len);

		if (ofp_sendto(fd, buf, strlen(buf), 0,
			       (struct ofp_sockaddr *)&addr,
			       sizeof(addr)) == -1) {
			OFP_ERR("Failed to send data (errno = %d)\n",
				ofp_errno);
		}
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = addr_mcast;
	mreq.imr_interface.s_addr = addr_local;
	if (ofp_setsockopt(fd, OFP_IPPROTO_IP, OFP_IP_DROP_MEMBERSHIP,
			   &mreq, sizeof(mreq)) == -1) {
		OFP_ERR("ofp_setsockopt() failed: %d.",
			ofp_errno);
	}

	ofp_close(fd);
	OFP_INFO("Multicast thread ended");
	return 0;
}

int ofp_multicast_thread(ofp_thread_t *thread_mcast, int core_id)
{
	odp_cpumask_t cpumask;
	ofp_thread_param_t thread_param = {0};

	odp_cpumask_zero(&cpumask);
	odp_cpumask_set(&cpumask, core_id);

	ofp_thread_param_init(&thread_param);
	thread_param.start = mcasttest;
	thread_param.arg = NULL;
	thread_param.thr_type = ODP_THREAD_CONTROL;

	return ofp_thread_create(thread_mcast, 1,
			       &cpumask, &thread_param);
}
