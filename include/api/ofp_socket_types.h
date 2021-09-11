/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __OFP_SOCKET_TYPES_H__
#define __OFP_SOCKET_TYPES_H__

#include <stdint.h>
#include "ofp_types.h"

#if __GNUC__ >= 4
#pragma GCC visibility push(default)
#endif

typedef uint8_t	__ofp_sa_family_t;
typedef uint32_t	__ofp_socklen_t;
typedef int32_t	__ofp_off_t;

#if __GNUC__ >= 4
#pragma GCC visibility pop
#endif

#endif /* __OFP_SOCKET_TYPES_H__ */

