#ifndef _MCAST_H_
#define _MCAST_H_

#include <odp_api.h>

#define PORT_CMD 2048

int ofp_multicast_thread(ofp_thread_t *thread_mcast, int core_id);

#endif
