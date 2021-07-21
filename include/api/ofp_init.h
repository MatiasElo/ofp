/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * @brief OFP initialization.
 *
 * OFP requires a global level init for the API library before the
 * other OFP APIs may be called.
 * - ofp_initialize()
 *
 * For a graceful termination the matching termination APIs exit
 * - ofp_terminate()
 */

#ifndef __OFP_INIT_H__
#define __OFP_INIT_H__

#include <odp_api.h>
#include "ofp_hook.h"
#include "ofp_ipsec_init.h"
#include "ofp_log.h"
#include "ofp_config.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

#define OFP_ODP_INSTANCE_INVALID ((odp_instance_t)(uintptr_t)(-1))

#define OFP_CLI_ADDR_TXT_SIZE 16	/* IPv4 address*/

#define OFP_CONTROL_CORE (-1)	/* Use the value of 'linux_core_id'*/
#define OFP_DFLT_CLI_CORE (-2)	/* Use the value of
				'ofp_cli_thread_config_t.core_id' */

/**
 * Checksum offloading configuration options bit field
 *
 * Packet IP/UDP/TCP checksum validation and insertion offloading
 * may be enabled or disabled:
 *
 * 0: Disable offloading.
 * 1: Enable offloading. This is the default value.
 *
 * When offloading is disabled, related checksums will be calculated by
 * software, if needed.
 *
 * When offloading is enabled, related checksums will be calculated either
 * by HW (if packet_io supports offloading) or by SW (if packet_io doesn't
 * support offloading), if needed.
 */
typedef struct ofp_chksum_offload_config_t {
	/** Enable IPv4 header checksum validation offload */
	uint16_t ipv4_rx_ena : 1;

	/** Enable UDP checksum validation offload */
	uint16_t udp_rx_ena  : 1;

	/** Enable TCP checksum validation offload */
	uint16_t tcp_rx_ena  : 1;

	/** Enable IPv4 header checksum insertion offload */
	uint16_t ipv4_tx_ena : 1;

	/** Enable UDP checksum insertion offload */
	uint16_t udp_tx_ena  : 1;

	/** Enable TCP checksum insertion offload */
	uint16_t tcp_tx_ena  : 1;
} ofp_chksum_offload_config_t;

/** OFP CLI thread configuration parameters */
typedef struct ofp_cli_thread_config_s {
	/** Start thread on OFP initialization
	 * Default value is 0
	*/
	odp_bool_t start_on_init;

	/** Port where CLI connections are waited.
	 * Default value is OFP_CLI_PORT_DFLT
	*/
	uint16_t port;

	/** Address where CLI connections are waited.
	 * Default value is OFP_CLI_ADDR_DFLT
	*/
	char addr[OFP_CLI_ADDR_TXT_SIZE];

	/** CPU core where CLI thread is pinned.
	 *  Default value is the value of 'linux_core_id'.
	*/
	int core_id;
} ofp_cli_thread_config_t;

/**
 * OFP API initialization data
 *
 * @see ofp_initialize_param()
 */
typedef struct ofp_initialize_param_t {
	/**
	 * ODP instance. The default value is OFP_ODP_INSTANCE_INVALID.
	 * If configured by application, it will be used in subsequent
	 * API calls. Application has the ownership on the instance and
	 * has to cleanup the resources (odp_term_global()).
	 * If not configured by application, OFP will create an ODP
	 * instance with default settings. OFP has ownership on the
	 * instance and will cleanup the resources (odp_term_global())
	 * at ofp_terminate() time.
	 */
	odp_instance_t instance;

	/**
	 * CPU core to which internal OFP control threads are pinned.
	 * The default value is 0.
	 */
	uint16_t linux_core_id;

	/**
	 * Count of interfaces to be initialized. The default value is
	 * 0.
	 */
	uint16_t if_count;

	/**
	 * Names of the interfaces to be initialized. The naming
	 * convention depends on the operating system and the ODP
	 * implementation. Must containg 'if_count' zero terminated
	 * strings.
	 */
	char if_names[OFP_FP_INTERFACE_MAX][OFP_IFNAMSIZ];

	/** Enable/disable the slow path interface management on the
	 * interfaces initialized by OFP.
	 *
	 * Default value is enable (1).
	 */
	odp_bool_t if_sp_mgmt;

	/**
	 * Slow path interface name offset. Slow path interface name for a
	 * network interface is composed from a fix part "sp" and a variable
	 * part formed from interface name offset + interface index e.g. "sp0".
	 *
	 * Default value is 0.
	 */
	uint16_t if_sp_offset;

	/**
	 * Packet input mode of the interfaces initialized by OFP.
	 * Must be ODP_PKTIN_MODE_SCHED if default_event_dispatcher()
	 * is used.
	 *
	 * Default value is ODP_PKTIN_MODE_SCHED.
	 */
	odp_pktin_mode_t pktin_mode;

	/**
	 * Packet output mode of the interfaces initialized by OFP.
	 *
	 * Default value is ODP_PKTOUT_MODE_DIRECT.
	 */
	odp_pktout_mode_t pktout_mode;

	/**
	 * Scheduler synchronization method of the pktin queues of the
	 * interfaces initialized by OFP in the scheduled mode.
	 * Ignored when pktin_mode is not ODP_PKTIN_MODE_SCHED.
	 *
	 * Default value is ODP_SCHED_SYNC_ATOMIC.
	 */
	odp_schedule_sync_t sched_sync;

	/**
	 * ODP event scheduling group for all scheduled event queues
	 * (pktio queues, timer queues and other queues) created in
	 * OFP initialization. The default value is
	 * ODP_SCHED_GROUP_ALL.
	 */
	odp_schedule_group_t sched_group;

	/**
	 * Packet processing hooks. The default value is NULL for
	 * every hook.
	 *
	 * @see ofp_hook.h
	 */
	ofp_pkt_hook pkt_hook[OFP_HOOK_MAX];

	/**
	 * Create netlink listener thread. If slow path is enabled,
	 * then default is TRUE, otherwise default is FALSE.
	 */
	odp_bool_t enable_nl_thread;

	/**
	 * Global ARP parameters.
	 */
	struct arp_s {
		/** Maximum number of ARP entries. Default is OFP_ARP_ENTRIES. */
		int entries;

		/** ARP hash bits. Default is OFP_ARP_HASH_BITS. */
		int hash_bits;

		/** Entry timeout in seconds. Default is OFP_ARP_ENTRY_TIMEOUT. */
		int entry_timeout;

		/**
		 * Timeout (in seconds) for a packet waiting for ARP
		 * to complete. Default is OFP_ARP_SAVED_PKT_TIMEOUT.
		 */
		int saved_pkt_timeout;

		/**
		 * Reply to an ARP request only if the target address of the
		 * request is an address of the receiving interface.
		 * Ignore the request otherwise.
		 *
		 * If not set, reply to an ARP request for any local IP
		 * address regardless of the receiving interface.
		 *
		 * See net.ipv4.conf.all.arp_ignore sysctl in Linux.
		 *
		 * Default value is 0.
		 */
		odp_bool_t check_interface;
	} arp;

	/**
	 * Maximum number of events received at once with the default
	 * event dispatched (default_event_dispatcher()).
	 * Default is OFP_EVT_RX_BURST_SIZE.
	 */
	int evt_rx_burst_size;

	/**
	 * Number of packets sent at once (>= 1).
	 * Default is OFP_PKT_TX_BURST_SIZE
	 */
	uint32_t pkt_tx_burst_size;

	struct pkt_pool_s {
		/** Packet pool size; Default value is SHM_PKT_POOL_NB_PKTS */
		int nb_pkts;

		/**
		 * Packet pool buffer size;
		 * Default value is SHM_PKT_POOL_BUFFER_SIZE
		 */
		unsigned long buffer_size;
	} pkt_pool;

	/**
	 * Maximum number of VLANs. Default is OFP_NUM_VLAN.
	 */
	int num_vlan;

	/**
	 * IPv4 route mtrie parameters.
	 */
	struct mtrie_s {
		/** Number of routes. Default is OFP_ROUTES. */
		int routes;
		/** Number of 8 bit mtrie nodes. Default is OFP_MTRIE_TABLE8_NODES. */
		int table8_nodes;
	} mtrie;

	/**
	 * Maximum number of VRFs. Default is OFP_NUM_VRF.
	 *
	 * VRF IDs used in interfaces and routes must be less than
	 * this value.
	 */
	int num_vrf;

	/**
	 * Checksum offloading options.
	 */
	ofp_chksum_offload_config_t chksum_offload;

	/*
	 * IPsec parameters
	 */
	struct ofp_ipsec_param ipsec;

	/*
	 * Socket parameters
	 */
	struct socket_s {
		/** Maximum number of sockets */
		uint32_t num_max;

		/** Socket descriptor offset.
		 *  Socket descriptors are returned in interval [sd_offset,
		 *  sd_offset + num_max -1]
		 */
		uint32_t sd_offset;
	} socket;

	/*
	 * TCP parameters
	 */
	struct tcp_s {
		/**
		 * Maximum number of TCP PCBs.
		 * Default value is OFP_NUM_PCB_TCP_MAX
		 */
		int pcb_tcp_max;

		/**
		 * Size of pcb hash.
		 * Must be a power of 2.
		 */
		int pcb_hashtbl_size;

		/**
		 * Size of pcbport hash.
		 * Must be a power of 2.
		 */
		int pcbport_hashtbl_size;

		/**
		 * Size of syncache hash.
		 * Must be a power of 2.
		 */
		int syncache_hashtbl_size;

		/**
		 * Maximum number of SACK holes.
		 * Default value is 4 * pcb_tcp_max
		 */
		int sackhole_max;
	} tcp;

	/*
	 * UDP parameters
	 */
	struct udp_s {
		/**
		 * Maximum number of UDP PCBs.
		 * Default value is OFP_NUM_PCB_UDP_MAX
		 */
		int pcb_udp_max;

		/**
		 * Size of pcb hash.
		 * Must be a power of 2.
		 */
		int pcb_hashtbl_size;

		/**
		 * Size of pcbport hash
		 * Must be a power of 2.
		 */
		int pcbport_hashtbl_size;
	} udp;

	/**
	 * Create default loopback interface lo0, 127.0.0.1/8.
	 * Interface can also be created with CLI or
	 * ofp_ifport_local_ipv4_up() API.
	 */
	odp_bool_t if_loopback;

	/**
	 * Log level
	 */
	enum ofp_log_level_s loglevel;

	/**
	 * Debug parameters
	 */
	struct debug_s {
		/**
		 * Bitmask options for printing traffic on file (and console) in
		 * text format and capturing traffic on file in pcap format.
		 *	bit 0: print packets from ODP to FP.
		 *		Use OFP_DEBUG_PRINT_RECV_NIC to set this flag.
		 *	bit 1: print packets from FP to ODP.
		 *		Use OFP_DEBUG_PRINT_SEND_NIC to set this flag.
		 *	bit 2: print packets from FP to SP.
		 *		Use OFP_DEBUG_PRINT_RECV_KNI to set this flag.
		 *	bit 3: print packets from SP to ODP.
		 *		Use OFP_DEBUG_PRINT_SEND_KNI to set this flag.
		 *	bit 4: print packets to console.
		 *		Use OFP_DEBUG_PRINT_CONSOLE to set this flag.
		 *	bit 6: capture packets to pcap file.
		 *		Use OFP_DEBUG_CAPTURE to set this flag.
		 */
		int flags;

		/**
		 * Name of the file where the packets are printed (text format)
		 * Default value is given by DEFAULT_DEBUG_TXT_FILE_NAME macro.
		 */
		char print_filename[OFP_FILE_NAME_SIZE_MAX];

		/**
		 * Bitmask of the ports for which the packets are captures
		 */
		int capture_ports;

		/**
		 * Name of the file where the packets are captured (pcap format)
		 * Default value is given by DEFAULT_DEBUG_PCAP_FILE_NAME macro.
		 */
		char capture_filename[OFP_FILE_NAME_SIZE_MAX];
	} debug;

	/**
	 * CLI parameters
	*/
	struct cli_s {
		/** Parameters coresponding to the CLI thread using OS sockets
		 * and bound address */
		ofp_cli_thread_config_t os_thread;

		/** Parameters coresponding to the CLI thread using OFP sockets
		 * and bound address */
		ofp_cli_thread_config_t ofp_thread;

		/**
		 * Enable execution of shutdown command.
		 * If set to true, the command will stop the execution of OFP
		 * internal threads and also user created OFP control and
		 * worker threads or processes (if were constructed to inspect
		 * the processing state of OFP (see ofp_get_processing_state()).
		 * If set to false, the shutdown cli command will report an
		 * error and operation will not take place.
		 * Default value is true.
		*/
		odp_bool_t enable_shutdown_cmd;
	} cli;
} ofp_initialize_param_t;

/**
 * OFP parameters
 *
 * @see ofp_get_parameters()
 */
typedef struct ofp_param_t {
	/**
	 * OFP API initialization data
	 */
	ofp_initialize_param_t global_param;
} ofp_param_t;

/**
 * Initialize ofp_initialize_param_t to its default values.
 *
 * This function should be called to initialize the supplied parameter
 * structure to default values before setting application specific values
 * and before passing the parameter structure to ofp_initialize().
 *
 * Using this function makes the application to some extent forward
 * compatible with future versions of OFP that may add new fields in
 * the parameter structure.
 *
 * If libconfig is enabled, a configuration file may be used. The
 * configuration file location may be set using the environment
 * variable OFP_CONF_FILE. If the environment variable is not set, the
 * file is read from $(sysconfdir)/ofp.conf, normally
 * /usr/local/etc/ofp.conf.
 *
 * See conf/README file for the configuration file detailed description.
 *
 * @param params structure to initialize
 *
 * @see ofp_initialize()
 */
void ofp_initialize_param(ofp_initialize_param_t *params);

/**
 * Initialize ofp_initialize_param_t according to a configuration file.
 *
 * This function is similar to ofp_initialize_param(), but allows the
 * caller to specify the location of the configuration file. Calling
 * this function with filename = NULL has the same effect as calling
 * ofp_initialize_param(). Passing a zero-length string as filename
 * means that no configuration file will be used, not even the default
 * or the file specified by the environment variable.
 *
 * @see ofp_initialize_param()
 *
 * @param params structure to initialize
 * @param filename name of the configuration file
 */
void ofp_initialize_param_from_file(ofp_initialize_param_t *params,
				    const char *filename);

/**
 * OFP initialization
 *
 * This function must be called only once for an application before
 * calling any other OFP API functions.
 *
 * If an ODP instance is provided as argument, it has to be called
 * from an ODP control thread.
 * If an ODP instance is not provided as argument, it will create an
 * ODP instance and will initialize current thread as control thread.
 *
 * @param params Structure with parameters for OFP initialization.
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
int ofp_initialize(ofp_initialize_param_t *params);

/**
 * OFP termination
 *
 * This function must be called only once in an OFP control
 * thread before exiting application.
 *
 * Should be called from a thread within the same schedule group specified in
 * the parameters of ofp_initialize().
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
int ofp_terminate(void);

/**
 * Thread or process resources initialization
 *
 * This API is called by functions like ofp_initialize(),
 * ofp_thread_create() and ofp_process_fork_n() to initialize thread or
 * process local resources.
 *
 * Application should not call this function unless it uses ODP API
 * directly to create threads or processes. In that case it must
 * call it before calling any other OFP API on that thread or process.
 *
 * @param description Thread or process short description. Takes a null
 * terminated string value or NULL if no description is given.
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_initialize() which must have been called prior to this.
 */
int ofp_init_local_resources(const char *description);

/**
 * Thread or process resources termination
 *
 * This API is called by OFP to cleanup local resources before
 * exiting a thread or process.
 *
 * Application should not call this function unless it used ODP API
 * directly to create threads or processes. In that case it should
 * call it after last OFP API of the thread was called.
 *
 * @retval 0 on success
 * @retval -1 on failure
 *
 * @see ofp_terminate() which may be called after this.
 */
int ofp_term_local_resources(void);

/**
 * Stop packet processing
 *
 * Stop processing threads
 *
 *
 * @retval ofp_get_processing_state() which may be called get
 *         the processing state
 *
 *
 * @see
 */
void ofp_stop_processing(void);

/**
 * Get address of processing state variable
 *
 * All processing loops should stop when
 * processing state turns 0
 *
 * @retval non NULL on success
 * @retval NULL on failure
 *
 * @see ofp_stop_processing() which may be called to stop the
 *      processing.
 */

odp_bool_t *ofp_get_processing_state(void);

/**
 * Get OFP parameters
 *
 * @param params Structure to be filled with OFP global parameters
 *
 * @retval 0 on success
 * @retval -1 on failure
 */

int ofp_get_parameters(ofp_param_t *params);

/**
 * Get ODP instance
 *
 * @retval ODP instance on success
 * @retval OFP_ODP_INSTANCE_INVALID on error
 */

odp_instance_t ofp_get_odp_instance(void);

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_INIT_H__ */
