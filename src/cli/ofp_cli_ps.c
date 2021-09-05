/* Copyright (c) 2021 Bogdan Pricope
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ofpi_cli.h"
#include "ofpi_global_param_shm.h"

static void print_threads(ofp_print_t *pr, odp_thrmask_t thrmask);

void f_ps(ofp_print_t *pr, const char *s)
{
	odp_thrmask_t thrmask;

	(void)s;

	ofp_print(pr, "Control threads/processes:\r\n");
	odp_thrmask_control(&thrmask);
	print_threads(pr, thrmask);

	ofp_print(pr, "Worker threads/processes:\r\n");
	odp_thrmask_worker(&thrmask);
	print_threads(pr, thrmask);
}

void f_help_ps(ofp_print_t *pr, const char *s)
{
	(void)s;

	ofp_print(pr, "Prints information on running threads/processes:\r\n"
		"  ps \r\n\r\n");

	ofp_print(pr, "Alternativ form of the command:\r\n"
		"  ps show\r\n\r\n");

	ofp_print(pr, "Show (this) help:\r\n"
		"  ps help\r\n\r\n");
}

static void print_threads(ofp_print_t *pr, odp_thrmask_t thrmask)
{
	int next_thr;

	ofp_print(pr, " Thread   Core       Description\r\n");
	next_thr = odp_thrmask_first(&thrmask);
	while (next_thr >= 0) {
		ofp_print(pr, "%7u %6d %14s\r\n",
			  next_thr,
			  V_global_thread_info[next_thr].cpu_id,
			  V_global_thread_info[next_thr].description);
		next_thr = odp_thrmask_next(&thrmask, next_thr);
	}
	ofp_print(pr, "\r\n");
}

