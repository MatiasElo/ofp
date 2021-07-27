/* Copyright (c) 2016, ENEA Software AB
 * Copyright (c) 2016, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>

#include "ofp.h"
#include "cli_arg_parse.h"

#define MAX_WORKERS		32

#define ENV_ARG "OFP_NETWRAP_ENV"
#define ENV_ARG_TKN_NUMBER_MAX 101

#define NETWRAP_APP_NAME "ofp_netwrap"
#define NETWRAP_APP_NAME_SIZE 12
/**
 * Get rid of path in filename - only for unix-type paths using '/'
 */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	appl_arg_ifs_t itf_param;
	char *cli_file;
} appl_args_t;

enum netwrap_state_enum {
	NETWRAP_UNINT = 0,
	NETWRAP_ODP_INIT_GLOBAL,
	NETWRAP_ODP_INIT_LOCAL,
	NETWRAP_OFP_INIT_GLOBAL,
	NETWRAP_WORKERS_STARTED
};

/**
 * helper funcs
 */
static int parse_env(appl_args_t *appl_args);
static int parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void parse_args_cleanup(appl_args_t *appl_args);
static int configure_interface_addresses(appl_arg_ifs_t *itf_param);
static void print_info(const char *progname, appl_args_t *appl_args,
		       odp_cpumask_t *cpumask);
static void usage(void);

static enum netwrap_state_enum netwrap_state;
static ofp_thread_t thread_tbl[MAX_WORKERS];
static int num_workers;
odp_instance_t netwrap_proc_instance;

__attribute__((destructor)) static void ofp_netwrap_main_dtor(void);

__attribute__((constructor)) static void ofp_netwrap_main_ctor(void)
{
	appl_args_t params;
	ofp_initialize_param_t app_init_params;
	ofp_thread_param_t thread_param;
	int ret_val, i;
	odp_cpumask_t cpumask_workers;

	netwrap_state = NETWRAP_UNINT;
	memset(&params, 0, sizeof(params));
	if (parse_env(&params) != EXIT_SUCCESS)
		return;

	/*
	 * Before any ODP API functions can be called, we must first init ODP
	 * globals, e.g. availale accelerators or software implementations for
	 * shared memory, threads, pool, qeueus, sheduler, pktio, timer, crypto
	 * and classification.
	 */
	if (odp_init_global(&netwrap_proc_instance, NULL, NULL)) {
		printf("Error: ODP global init failed.\n");
		parse_args_cleanup(&params);
		return;
	}
	netwrap_state = NETWRAP_ODP_INIT_GLOBAL;
	/*
	 * When the global ODP level init has been done, we can now issue a
	 * local init per thread. This must also be done before any other ODP
	 * API calls may be made. Local inits are made here for shared memory,
	 * threads, pktio and scheduler.
	 */
	if (odp_init_local(netwrap_proc_instance, ODP_THREAD_CONTROL) != 0) {
		printf("Error: ODP local init failed.\n");
		parse_args_cleanup(&params);
		ofp_netwrap_main_dtor();
		return;
	}
	netwrap_state = NETWRAP_ODP_INIT_LOCAL;

	/*
	 * Now that ODP has been initalized, we can initialize OFP. This will
	 * open a pktio instance for each interface supplied as argument by the
	 * user.
	 *
	 * General configuration will be to pktio and schedluer queues here in
	 * addition will fast path interface configuration.
	 */
	ofp_initialize_param(&app_init_params);
	app_init_params.cli.os_thread.start_on_init = 1;
	app_init_params.if_count = params.itf_param.if_count;
	for (i = 0; i < params.itf_param.if_count &&
	     i < OFP_FP_INTERFACE_MAX; i++) {
		strncpy(app_init_params.if_names[i],
			params.itf_param.if_array[i].if_name,
			OFP_IFNAMSIZ);
		app_init_params.if_names[i][OFP_IFNAMSIZ - 1] = '\0';
	}
	app_init_params.instance = netwrap_proc_instance;

	if (ofp_initialize(&app_init_params) != 0) {
		printf("Error: OFP global init failed.\n");
		parse_args_cleanup(&params);
		ofp_netwrap_main_dtor();
		return;
	}

	/*
	 * Get the default workers to cores distribution: one
	 * run-to-completion worker thread or process can be created per core.
	 */
	if (ofp_get_default_worker_cpumask(params.core_count, MAX_WORKERS,
					   &cpumask_workers)) {
		OFP_ERR("Error: Failed to get the default workers to cores "
			"distribution\n");
		parse_args_cleanup(&params);
		ofp_netwrap_main_dtor();
		return;
	}
	num_workers = odp_cpumask_count(&cpumask_workers);

	/* Print both system and application information */
	print_info(NETWRAP_APP_NAME, &params, &cpumask_workers);

	netwrap_state = NETWRAP_OFP_INIT_GLOBAL;

	/*
	 * Create and launch dataplane dispatcher worker threads to be placed
	 * according to the cpumask, thread_tbl will be populated with the
	 * created pthread IDs.
	 *
	 * In this example, all threads will run the default_event_dispatcher
	 * function with ofp_eth_vlan_processing as argument.
	 */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	ofp_thread_param_init(&thread_param);
	thread_param.start = default_event_dispatcher;
	thread_param.arg = ofp_eth_vlan_processing;
	thread_param.thr_type = ODP_THREAD_WORKER;

	ret_val = ofp_thread_create(thread_tbl, num_workers,
				    &cpumask_workers, &thread_param);
	if (ret_val != num_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d",
			num_workers, ret_val);
		ofp_stop_processing();
		if (ret_val != -1)
			ofp_thread_join(thread_tbl, ret_val);
		parse_args_cleanup(&params);
		ofp_netwrap_main_dtor();
		return;
	}
	netwrap_state = NETWRAP_WORKERS_STARTED;

	/* Configure IP addresses */
	if (configure_interface_addresses(&params.itf_param)) {
		OFP_ERR("Error: Failed to configure addresses");
		ofp_stop_processing();
		ofp_thread_join(thread_tbl, num_workers);
		parse_args_cleanup(&params);
		ofp_netwrap_main_dtor();
		return;
	}

	/*
	 * Process the CLI commands file (if defined).
	 * This is an alternative way to set the IP addresses and other
	 * parameters.
	 */
	if (ofp_cli_process_file(params.cli_file)) {
		OFP_ERR("Error: Failed to process CLI file");
		ofp_stop_processing();
		ofp_thread_join(thread_tbl, num_workers);
		parse_args_cleanup(&params);
		ofp_netwrap_main_dtor();
		return;
	}

	parse_args_cleanup(&params);

	sleep(1);

	OFP_INFO("End Netwrap processing constructor()\n");
}

__attribute__((destructor))
static void ofp_netwrap_main_dtor(void)
{
	ofp_stop_processing();

	switch (netwrap_state) {
	case NETWRAP_WORKERS_STARTED:
	/*
	 * Wait here until all worker threads have terminated, then free up all
	 * resources allocated by odp_init_global().
	 */
		ofp_thread_join(thread_tbl, num_workers);
		/* fall through */
	case NETWRAP_OFP_INIT_GLOBAL:
		if (ofp_terminate() < 0)
			printf("Error: ofp_terminate failed\n");
		/* fall through */
	case NETWRAP_ODP_INIT_LOCAL:
		if (odp_term_local() < 0)
			printf("Error: odp_term_local failed\n");
		/* fall through */
	case NETWRAP_ODP_INIT_GLOBAL:
		if (odp_term_global(netwrap_proc_instance) < 0)
			printf("Error: odp_term_global failed\n");
		/* fall through */
	case NETWRAP_UNINT:
		;
	};
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static int parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt, res;
	int long_index;
	size_t len;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"cli-file", required_argument,
			NULL, 'f'},/* return 'f' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:hpf:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			res = ofpexpl_parse_interfaces(optarg,
						       &appl_args->itf_param);
			if (res == EXIT_FAILURE) {
				usage();
				parse_args_cleanup(appl_args);
				return EXIT_FAILURE;
			}
			break;

		case 'h':
			usage();
			parse_args_cleanup(appl_args);
			return EXIT_FAILURE;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage();
				parse_args_cleanup(appl_args);
				return EXIT_FAILURE;
			}
			len += 1;	/* add room for '\0' */

			appl_args->cli_file = malloc(len);
			if (appl_args->cli_file == NULL) {
				usage();
				parse_args_cleanup(appl_args);
				return EXIT_FAILURE;
			}

			strcpy(appl_args->cli_file, optarg);
			break;

		default:
			break;
		}
	}

	if (appl_args->itf_param.if_count == 0) {
		usage();
		parse_args_cleanup(appl_args);
		return EXIT_FAILURE;
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */

	return EXIT_SUCCESS;
}

/**
 * Cleanup cli parameters
 */
static void parse_args_cleanup(appl_args_t *appl_args)
{
	ofpexpl_parse_interfaces_param_cleanup(&appl_args->itf_param);
}

static int parse_env(appl_args_t *appl_args)
{
	char *netwrap_env;
	char *netwrap_env_temp;
	char *argv[ENV_ARG_TKN_NUMBER_MAX];
	char app_name[NETWRAP_APP_NAME_SIZE + 1];
	int argc = 0;

	netwrap_env = getenv(ENV_ARG);
	if (!netwrap_env)
		return EXIT_FAILURE;

	netwrap_env = strdup(netwrap_env);

	strcpy(app_name, NETWRAP_APP_NAME);
	argv[argc++] = app_name;
	netwrap_env_temp = strtok(netwrap_env, " \0");
	while (netwrap_env_temp && argc < ENV_ARG_TKN_NUMBER_MAX) {
		argv[argc++] = netwrap_env_temp;
		netwrap_env_temp = strtok(NULL, " \0");
	}

	/* Parse and store the application arguments */
	if (parse_args(argc, argv, appl_args) != EXIT_SUCCESS)
		return EXIT_FAILURE;

	free(netwrap_env);
	return EXIT_SUCCESS;
}

/**
 * Print system and application info
 */
static void print_info(const char *progname, appl_args_t *appl_args,
		       odp_cpumask_t *cpumask)
{
	int i;
	char cpumaskstr[64];

	printf("\n"
		   "ODP system info\n"
		   "---------------\n"
		   "ODP API version: %s\n"
		   "CPU model:       %s\n"
		   "CPU freq (hz):   %"PRIu64"\n"
		   "Cache line size: %i\n"
		   "Core count:      %i\n"
		   "\n",
		   odp_version_api_str(), odp_cpu_model_str(),
		   odp_cpu_hz(), odp_sys_cache_line_size(),
		   odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
		   "-----------------\n"
		   "IF-count:        %i\n"
		   "Using IFs:      ",
		   progname, appl_args->itf_param.if_count);
	for (i = 0; i < appl_args->itf_param.if_count; ++i)
		printf(" %s", appl_args->itf_param.if_array[i].if_name);
	printf("\n\n");

	/* Print worker to core distribution */
	if (odp_cpumask_to_str(cpumask, cpumaskstr, sizeof(cpumaskstr)) < 0) {
		printf("Error: Too small buffer provided to "
			"odp_cpumask_to_str\n");
		strcpy(cpumaskstr, "Unknown");
	}

	printf("Num worker threads: %i\n", odp_cpumask_count(cpumask));
	printf("first CPU:          %i\n", odp_cpumask_first(cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(void)
{
	printf("\n"
		   "Usage:\n"
		   "    export %s=\"OPTIONS\"\n"
		   "    ofp_netwrap.sh <application full path>\n"
		   "  E.g.:\n"
		   "    export %s=\"-i eth1@192.168.100.10/24\"\n"
		   "    ofp_netwrap.sh /tmp/in_udp\n"
		   ""
		   "\n"
		   "Mandatory OPTIONS:\n"
		   "  -i, --interface <interfaces> Ethernet interface list"
		   " (comma-separated, no spaces)\n"
		   "  Example:\n"
		   "    eth1,eth2\n"
		   "    eth1@192.168.100.10/24,eth2@172.24.200.10/16\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", ENV_ARG, ENV_ARG);
}

/**
 * Configure IPv4 addresses
 *
 * @param itf_param appl_arg_ifs_t Interfaces to configure
 * @return int 0 on success, -1 on error
 *
 */
static int configure_interface_addresses(appl_arg_ifs_t *itf_param)
{
	struct appl_arg_if *ifarg = NULL;
	ofp_ifnet_t ifnet = OFP_IFNET_INVALID;
	uint32_t addr = 0;
	int port = 0;
	uint16_t subport = 0;
	int i, ret = 0;
	const char *res = NULL;

	for (i = 0; i < itf_param->if_count && i < OFP_FP_INTERFACE_MAX; i++) {
		ifarg = &itf_param->if_array[i];

		if (!ifarg->if_name) {
			OFP_ERR("Error: Invalid interface name: null");
			ret = -1;
			break;
		}

		if (!ifarg->if_address)
			continue; /* Not set through application parameters*/

		OFP_DBG("Setting %s/%d on %s", ifarg->if_address,
			ifarg->if_address_masklen, ifarg->if_name);

		ifnet = ofp_ifport_net_ifnet_get_by_name(ifarg->if_name);
		if (ifnet == OFP_IFNET_INVALID) {
			OFP_ERR("Error: interface not found: %s",
				ifarg->if_name);
			ret = -1;
			break;
		}

		if (ofp_ifnet_port_get(ifnet, &port, &subport)) {
			OFP_ERR("Error: Failed to get <port, sub-port>: %s",
				ifarg->if_name);
			ret = -1;
			break;
		}

		if (!ofp_parse_ip_addr(ifarg->if_address, &addr)) {
			OFP_ERR("Error: Failed to parse IPv4 address: %s",
				ifarg->if_address);
			ret = -1;
			break;
		}

		res = ofp_ifport_net_ipv4_up(port, subport, 0, addr,
					     ifarg->if_address_masklen, 1);
		if (res != NULL) {
			OFP_ERR("Error: Failed to set IPv4 address %s "
				"on interface %s: %s",
				ifarg->if_address, ifarg->if_name, res);
			ret = -1;
			break;
		}
	}

	return ret;
}
