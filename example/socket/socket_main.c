/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "ofp.h"
#include "socket_util.h"
#include "suite_framework.h"
#include "socket_create_close.h"
#include "socket_bind.h"
#include "socket_shutdown.h"
#include "socket_connect_udp.h"
#include "socket_send_sendto_udp.h"
#include "socket_send_recv_udp.h"
#include "socket_listen_tcp.h"
#include "socket_connect_accept_tcp.h"
#include "socket_send_recv_tcp.h"
#include "socket_select.h"
#include "socket_sigevent.h"

#define MAX_WORKERS		32

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *cli_file;
} appl_args_t;


/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args,
		       odp_cpumask_t *cpumask);
static void usage(char *progname);

/*static int null_function(int fd)
{
	(void)fd;

	return 0;
}*/

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

/** main() Application entry point
 *
 * @param argc int
 * @param argv[] char*
 * @return int
 *
 */
int main(int argc, char *argv[])
{
	ofp_global_param_t app_init_params;
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	appl_args_t params;
	int num_workers, ret_val, i;
	odp_cpumask_t cpumask;
	odph_odpthread_params_t thr_params;
	odp_instance_t instance;

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

	/*
	 * This example assumes that core #0 and #1 runs Linux kernel
	 * background tasks and control threads.
	 * By default, cores #2 and beyond will be populated with a OFP
	 * processing threads each.
	 */
	ofp_init_global_param(&app_init_params);
	app_init_params.if_count = params.if_count;
	for (i = 0; i < params.if_count && i < OFP_FP_INTERFACE_MAX; i++) {
		strncpy(app_init_params.if_names[i], params.if_names[i],
			OFP_IFNAMSIZ);
		app_init_params.if_names[i][OFP_IFNAMSIZ - 1] = '\0';
	}

	if (ofp_init_global(&app_init_params)) {
		OFP_ERR("Error: OFP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Get the default workers to cores distribution: one
	 * run-to-completion worker thread or process can be created per core.
	 */
	if (ofp_get_default_worker_cpumask(params.core_count, MAX_WORKERS,
					   &cpumask)) {
		OFP_ERR("Error: Failed to get the default workers to cores "
			"distribution\n");
		ofp_term_global();
		return EXIT_FAILURE;
	}
	num_workers = odp_cpumask_count(&cpumask);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params, &cpumask);

	/* Start dataplane dispatcher worker threads */
	instance = ofp_get_odp_instance();
	if (OFP_ODP_INSTANCE_INVALID == instance) {
		OFP_ERR("Error: Invalid odp instance.\n");
		ofp_term_global();
		exit(EXIT_FAILURE);
	}
	memset(thread_tbl, 0, sizeof(thread_tbl));
	thr_params.start = default_event_dispatcher;
	thr_params.arg = ofp_eth_vlan_processing;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;
	ret_val = odph_odpthreads_create(thread_tbl,
					 &cpumask,
					 &thr_params);
	if (ret_val != num_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d",
			num_workers, ret_val);
		ofp_stop_processing();
		odph_odpthreads_join(thread_tbl);
		ofp_term_global();
		return EXIT_FAILURE;
	}

	sleep(2);
	/* Start CLI */
	ofp_start_cli_thread(app_init_params.linux_core_id, params.cli_file);
	sleep(5);

	ofp_loglevel_set(OFP_LOG_INFO);

	config_suite_framework(app_init_params.linux_core_id);

	OFP_INFO("\n\nSuite: IPv4 UDP socket: create and close.\n\n");
	if (!init_suite(NULL))
		run_suite(instance, create_close_udp, create_close_udp_noproto);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket: create and close.\n\n");
	if (!init_suite(NULL))
		run_suite(instance, create_close_tcp, create_close_tcp_noproto);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP socket: create and close.\n\n");
	if (!init_suite(NULL))
		run_suite(instance, create_close_udp6, create_close_udp6_noproto);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 TCP socket: create and close.\n\n");
	if (!init_suite(NULL))
		run_suite(instance, create_close_tcp6, create_close_tcp6_noproto);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /* INET6 */

	OFP_INFO("\n\nSuite: IPv4 UDP socket: bind.\n\n");
	if (!init_suite(init_udp_create_socket))
		run_suite(instance, bind_ip4_local_ip, bind_ip4_any);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket: bind.\n\n");
	if (!init_suite(init_tcp_create_socket))
		run_suite(instance, bind_ip4_local_ip, bind_ip4_any);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP socket: bind.\n\n");
	if (!init_suite(init_udp6_create_socket))
		run_suite(instance, bind_ip6_local_ip, bind_ip6_any);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 TCP socket: bind.\n\n");
	if (!init_suite(init_tcp6_create_socket))
		run_suite(instance, bind_ip6_local_ip, bind_ip6_any);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /* INET6 */

	OFP_INFO("\n\nSuite: IPv4 UDP socket: shutdown.\n\n");
	if (!init_suite(init_udp_create_socket))
		run_suite(instance, shutdown_socket, shutdown_socket);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket: shutdown (no connection).\n\n");
	if (!init_suite(init_tcp_create_socket))
		run_suite(instance, shutdown_socket, shutdown_socket);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP socket: shutdown.\n\n");
	if (!init_suite(init_udp6_create_socket))
		run_suite(instance, shutdown_socket, shutdown_socket);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 TCP socket: shutdown (no connection).\n\n");
	if (!init_suite(init_tcp6_create_socket))
		run_suite(instance, shutdown_socket, shutdown_socket);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /* INET6 */

	OFP_INFO("\n\nSuite: IPv4 UDP socket: connect.\n\n");
	if (!init_suite(init_udp_create_socket))
		run_suite(instance, connect_udp4, connect_bind_udp4);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 UDP socket: connect + shutdown.\n\n");
	if (!init_suite(init_udp_create_socket))
		run_suite(instance, connect_shutdown_udp4, connect_shutdown_bind_udp4);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP socket: connect.\n\n");
	if (!init_suite(init_udp6_create_socket))
		run_suite(instance, connect_udp6, connect_bind_udp6);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 UDP socket: connect + shutdown.\n\n");
	if (!init_suite(init_udp6_create_socket))
		run_suite(instance, connect_shutdown_udp6, connect_shutdown_bind_udp6);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 UDP socket: connect + shutdown + any.\n\n");
	if (!init_suite(init_udp6_create_socket))
		run_suite(instance, connect_shutdown_udp6_any,
				connect_shutdown_bind_udp6_any);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /* INET6 */

	OFP_INFO("\n\nSuite: IPv4 UDP socket BIND local address: send + sendto\n\n");
	if (!init_suite(init_udp_bind_local_ip))
		run_suite(instance, send_ip4_udp_local_ip, sendto_ip4_udp_local_ip);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 UDP socket bind any address: send + sendto\n\n");
	if (!init_suite(init_udp_bind_any))
		run_suite(instance, send_ip4_udp_any, sendto_ip4_udp_any);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP socket BIND local address: send + sendto\n\n");
	if (!init_suite(init_udp6_bind_local_ip))
		run_suite(instance, send_ip6_udp_local_ip, sendto_ip6_udp_local_ip);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 UDP socket bind any address: send + sendto\n\n");
	if (!init_suite(init_udp6_bind_any))
		run_suite(instance, send_ip6_udp_any, sendto_ip6_udp_any);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /* INET6 */

	OFP_INFO("\n\nSuite: IPv4 UDP bind local IP: sendto + recv.\n\n");
	if (!init_suite(init_udp_local_ip))
		run_suite(instance, send_udp_local_ip, recv_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 UDP bind loopback IP: sendto + recv.\n\n");
	if (!init_suite(init_udp_loopback))
		run_suite(instance, send_udp_loopback, recv_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 UDP bind local IP: sendto + recvfrom.\n\n");
	if (!init_suite(init_udp_bind_local_ip))
		run_suite(instance, send_udp_local_ip, recvfrom_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 UDP bind any address: sendto + recv.\n\n");
	if (!init_suite(init_udp_any))
		run_suite(instance, send_udp_any, recv_udp);
	end_suite();

	OFP_INFO("\n\nSuite: IPv4 UDP bind any address: sendto + recvfrom.\n\n");
	if (!init_suite(init_udp_bind_any))
		run_suite(instance, send_udp_any, recvfrom_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 UDP bind any address: sendto + recvfrom(NULL addr).\n\n");
	if (!init_suite(init_udp_bind_any))
		run_suite(instance, send_udp_any, recvfrom_udp_null_addr);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP bind local IP: sendto + recv.\n\n");
	if (!init_suite(init_udp6_bind_local_ip))
		run_suite(instance, send_udp6_local_ip, recv_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 UDP bind local IP: sendto + recvfrom.\n\n");
	if (!init_suite(init_udp6_bind_local_ip))
		run_suite(instance, send_udp6_local_ip, recvfrom_udp6);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 UDP bind any IP: sendto + recv.\n\n");
	if (!init_suite(init_udp6_bind_any))
		run_suite(instance, send_udp6_any, recv_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 UDP bind any IP: sendto + recvfrom.\n\n");
	if (!init_suite(init_udp6_bind_any))
		run_suite(instance, send_udp6_any, recvfrom_udp6);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 UDP bind any IP: sendto + recvfrom(NULL addr).\n\n");
	if (!init_suite(init_udp6_bind_any))
		run_suite(instance, send_udp6_any, recvfrom_udp_null_addr);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	OFP_INFO("\n\nSuite: IPv4 TCP socket local IP: listen.\n\n");
	if (!init_suite(init_tcp_bind_local_ip))
		run_suite(instance, listen_tcp, listen_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 TCP socket local IP: listen.\n\n");
	if (!init_suite(init_tcp6_bind_local_ip))
		run_suite(instance, listen_tcp, listen_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	OFP_INFO("\n\nSuite: IPv4 TCP socket local IP: connect + accept.\n\n");
	if (!init_suite(init_tcp_bind_listen_local_ip))
		run_suite(instance, connect_tcp4_local_ip, accept_tcp4);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket any IP: connect + accept.\n\n");
	if (!init_suite(init_tcp_bind_listen_any))
		run_suite(instance, connect_tcp4_any, accept_tcp4);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket local IP: connect + accept null address.\n\n");
	if (!init_suite(init_tcp_bind_listen_local_ip))
		run_suite(instance, connect_tcp4_local_ip, accept_tcp4_null_addr);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 TCP socket local IP: connect + accept.\n\n");
	if (!init_suite(init_tcp6_bind_listen_local_ip))
		run_suite(instance, connect_tcp6_local_ip, accept_tcp6);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 TCP socket any IP: connect + accept.\n\n");
	if (!init_suite(init_tcp6_bind_listen_any))
		run_suite(instance, connect_tcp6_any, accept_tcp6);
	end_suite();
	OFP_INFO("Test ended.\n");


	OFP_INFO("\n\nSuite: IPv6 TCP socket local IP: connect + accept null address.\n\n");
	if (!init_suite(init_tcp6_bind_listen_local_ip))
		run_suite(instance, connect_tcp6_local_ip, accept_tcp6_null_addr);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	OFP_INFO("\n\nSuite: IPv4 TCP socket local IP: send + recv.\n\n");
	if (!init_suite(init_tcp_bind_listen_local_ip))
		run_suite(instance, send_tcp4_local_ip, receive_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket any IP: send + recv.\n\n");
	if (!init_suite(init_tcp_bind_listen_any))
		run_suite(instance, send_tcp4_any, receive_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket any IP: multi send + recv.\n\n");
	if (!init_suite(init_tcp_bind_listen_any))
		run_suite(instance, send_multi_tcp4_any, receive_multi_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP socket any IP: 2 * send \
			+ recv(OFP_MSG_WAITALL).\n\n");
	if (!init_suite(init_tcp_bind_listen_any))
		run_suite(instance, send_tcp4_msg_waitall, receive_tcp4_msg_waitall);
	end_suite();
	OFP_INFO("Test ended.\n");


#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 TCP socket local IP: send + recv.\n\n");
	if (!init_suite(init_tcp6_bind_listen_local_ip))
		run_suite(instance, send_tcp6_local_ip, receive_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 TCP socket any IP: send + recv.\n\n");
	if (!init_suite(init_tcp6_bind_listen_any))
		run_suite(instance, send_tcp6_any, receive_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	OFP_INFO("\n\nSuite: IPv4 UDP bind local IP: select + recv.\n\n");
	if (!init_suite(init_udp_bind_local_ip))
		run_suite(instance, send_udp_local_ip, select_recv_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 TCP bind local IP: select + accept + recv.\n\n");
	if (!init_suite(init_tcp_bind_listen_local_ip))
		run_suite(instance, send_tcp4_local_ip, select_recv_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP bind local IP: select + recv.\n\n");
	if (!init_suite(init_udp6_bind_local_ip))
		run_suite(instance, send_udp6_local_ip, select_recv_udp);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv6 TCP bind local IP: select + accept + recv.\n\n");
	if (!init_suite(init_tcp6_bind_listen_local_ip))
		run_suite(instance, send_tcp6_local_ip, select_recv_tcp);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	OFP_INFO("\n\nSuite: IPv4 UDP bindlocal IP: select + recv x2.\n\n");
	if (!init_suite(init_udp_bind_local_ip))
		run_suite(instance, send_udp_local_ip, select_recv_udp_2);
	end_suite();
	OFP_INFO("Test ended.\n");

	OFP_INFO("\n\nSuite: IPv4 UDP bind local IP: socket_sigevent rcv.\n\n");
	if (!init_suite(init_udp_bind_local_ip))
		run_suite(instance, recv_send_udp_local_ip, socket_sigevent_udp4);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 UDP bind local IP: socket_sigevent rcv.\n\n");
	if (!init_suite(init_udp6_bind_local_ip))
		run_suite(instance, recv_send_udp6_local_ip, socket_sigevent_udp6);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	OFP_INFO("\n\nSuite: IPv4 TCP bind local IP: socket_sigevent rcv.\n\n");
	if (!init_suite(init_tcp_bind_listen_local_ip))
		run_suite(instance, connect_recv_send_tcp_local_ip, socket_sigevent_tcp_rcv);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 TCP bind local IP: socket_sigevent rcv.\n\n");
	if (!init_suite(init_tcp6_bind_listen_local_ip))
		run_suite(instance, connect_recv_send_tcp6_local_ip, socket_sigevent_tcp_rcv);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	OFP_INFO("\n\nSuite: IPv4 TCP bind local IP: socket_sigevent accept.\n\n");
	if (!init_suite(init_tcp_bind_listen_local_ip))
		run_suite(instance, connect_tcp_delayed_local_ip, socket_sigevent_tcp_accept);
	end_suite();
	OFP_INFO("Test ended.\n");

#ifdef INET6
	OFP_INFO("\n\nSuite: IPv6 TCP bind local IP: socket_sigevent accept.\n\n");
	if (!init_suite(init_tcp6_bind_listen_local_ip))
		run_suite(instance, connect_tcp6_delayed_local_ip,
			socket_sigevent_tcp_accept);
	end_suite();
	OFP_INFO("Test ended.\n");
#endif /*INET6*/

	odph_odpthreads_join(thread_tbl);

	if (ofp_term_global() < 0)
		printf("Error: ofp_term_global failed.\n");

	printf("End Main()\n");
	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *names, *str, *token, *save;
	size_t len;
	int i;
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
		opt = getopt_long(argc, argv, "+c:i:hf:",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->core_count = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			names = malloc(len);
			if (names == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
			}
			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(names, optarg);
			for (str = names, i = 0;; str = NULL, i++) {
				token = strtok_r(str, ",", &save);
				if (token == NULL)
					break;
				appl_args->if_names[i] = token;
			}
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		case 'f':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->cli_file = malloc(len);
			if (appl_args->cli_file == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->cli_file, optarg);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args,
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
		   progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
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
static void usage(char *progname)
{
	printf("\n"
		   "Usage: %s OPTIONS\n"
		   "  E.g. %s -i eth1,eth2,eth3\n"
		   "\n"
		   "ODPFastpath application.\n"
		   "\n"
		   "Mandatory OPTIONS:\n"
		   "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
		   "\n"
		   "Optional OPTIONS\n"
		   "  -c, --count <number> Core count.\n"
		   "  -h, --help           Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
