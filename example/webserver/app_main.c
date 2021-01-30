/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#include <getopt.h>
#include <string.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "ofp.h"
#include "linux_sigaction.h"
#include "linux_resources.h"
#include "httpd.h"

#define MAX_WORKERS		32

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
				strrchr((file_name), '/') + 1 : (file_name))

/**
 * Parsed command line application arguments
 */
typedef struct {
	int core_count;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *cli_file;
	char *root_dir;
	uint16_t lport;
	odp_bool_t use_epoll;
} appl_args_t;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args,
		       odp_cpumask_t *cpumask);
static void usage(char *progname);

/** main() Application entry point
 *
 * @param argc int
 * @param argv[] char*
 * @return int
 *
 */
int main(int argc, char *argv[])
{
	appl_args_t params;
	ofp_initialize_param_t app_init_params;
	ofp_thread_t thread_tbl[MAX_WORKERS];
	ofp_thread_t webserver_pthread = {0};
	ofp_thread_param_t thread_param;
	webserver_arg_t webserver_pthread_arg = {0};
	int num_workers, new_workers, i;
	odp_cpumask_t cpumask_workers;

	ofpexpl_resources_set();

	/* add handler for Ctr+C */
	if (ofpexpl_sigaction_set(ofpexpl_sigfunction_stop)) {
		printf("Error: failed to set signal actions.\n");
		return EXIT_FAILURE;
	}

	/* Parse and store the application arguments */
	parse_args(argc, argv, &params);

	/*
	 * This example assumes that core #0 and #1 runs Linux kernel
	 * background tasks and control threads.
	 * By default, cores #2 and beyond will be populated with a OFP
	 * processing threads (workers).
	 */
	ofp_initialize_param(&app_init_params);
	app_init_params.if_count = params.if_count;
	for (i = 0; i < params.if_count && i < OFP_FP_INTERFACE_MAX; i++) {
		strncpy(app_init_params.if_names[i], params.if_names[i],
			OFP_IFNAMSIZ);
		app_init_params.if_names[i][OFP_IFNAMSIZ - 1] = '\0';
	}

	if (ofp_initialize(&app_init_params)) {
		printf("Error: OFP global init failed.\n");
		return EXIT_FAILURE;
	}

	/*
	 * Get the default workers to cores distribution: one
	 * run-to-completion worker thread or process can be created per core.
	 */
	if (ofp_get_default_worker_cpumask(params.core_count, MAX_WORKERS,
					   &cpumask_workers)) {
		OFP_ERR("Error: Failed to get the default workers to cores "
			"distribution\n");
		ofp_terminate();
		return EXIT_FAILURE;
	}
	num_workers = odp_cpumask_count(&cpumask_workers);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &params, &cpumask_workers);

	/* Start dataplane dispatcher worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	ofp_thread_param_init(&thread_param);
	thread_param.start = default_event_dispatcher;
	thread_param.arg = ofp_eth_vlan_processing;
	thread_param.thr_type = ODP_THREAD_WORKER;

	new_workers = ofp_thread_create(thread_tbl, num_workers,
					&cpumask_workers, &thread_param);
	if (num_workers != new_workers) {
		OFP_ERR("Error: Failed to create worker threads, "
			"expected %d, got %d",
			num_workers, new_workers);
		ofp_stop_processing();
		if (new_workers != -1)
			ofp_thread_join(thread_tbl, new_workers);
		ofp_terminate();
		return EXIT_FAILURE;
	}

	/* other app code here.*/
	/* Start CLI */
	ofp_start_cli_thread(app_init_params.linux_core_id, params.cli_file);

	/* webserver */
	webserver_pthread_arg.root_dir = params.root_dir;
	webserver_pthread_arg.lport = params.lport;
	webserver_pthread_arg.use_epoll = params.use_epoll;
	if (ofp_start_webserver_thread(&webserver_pthread,
				       app_init_params.linux_core_id,
				       &webserver_pthread_arg) != 1) {
		OFP_ERR("Error: Failed to create webserver thread");
		ofp_thread_join(thread_tbl, num_workers);
		ofp_terminate();
		return EXIT_FAILURE;
	}

	ofp_thread_join(thread_tbl, num_workers);
	ofp_thread_join(&webserver_pthread, 1);

	if (params.root_dir) {
		free(params.root_dir);
		params.root_dir = NULL;
	}
	if (ofp_terminate() < 0)
		printf("Error: ofp_terminate failed.\n");

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
		{"core_count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{"cli-file", required_argument,
			NULL, 'f'},/* return 'f' */
		{"root", required_argument, NULL, 'r'},	/* return 'r' */
		{"lport", required_argument, NULL, 'p'},	/* return 'p' */
		{"epoll", no_argument, NULL, 'e'}, /* return 'e' */
		{NULL, 0, NULL, 0}
	};

	memset(appl_args, 0, sizeof(*appl_args));
	appl_args->use_epoll = 0;

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:hf:r:ep:",
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
		case 'r':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			appl_args->root_dir = strdup(optarg);
			break;
		case 'e':
			appl_args->use_epoll = 1;
			break;
		case 'p':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			appl_args->lport = (uint16_t)atoi(optarg);
			break;
		default:
			break;
		}
	}

	if (appl_args->if_count == 0) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (!appl_args->root_dir)
		appl_args->root_dir = strdup(DEFAULT_ROOT_DIRECTORY);
	if (!appl_args->lport)
		appl_args->lport = DEFAULT_BIND_PORT;

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
		   "  -r, --root <web root folder> Webserver root folder.\n"
		   "\tDefault: " DEFAULT_ROOT_DIRECTORY "\n"
		   "  -p, --lport <port> Port address were webserver binds.\n"
			"\tDefault: %d\n"
		   "  -e, --epoll Use epoll method.\n"
		   "\tDefault: select method.\n"
		   "  -h, --help  Display help and exit.\n"
		   "\n", NO_PATH(progname), NO_PATH(progname), DEFAULT_BIND_PORT
		);
}
