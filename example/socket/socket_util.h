/* Copyright (c) 2014, ENEA Software AB
 * Copyright (c) 2014, Nokia
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

#ifndef __SOCKET_UTIL_H__
#define __SOCKET_UTIL_H__

#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#define IP4(a, b, c, d) (a|(b<<8)|(c<<16)|(d<<24))

#define TEST_PORT 54321

#define TEST_ADDR4_STR "192.168.100.1"
#define TEST_ADDR4 IP4(192,168,100,1)
#define TEST_ADDR4_MASK 24

#define TEST_ADDR6_STR "fd00:1baf::1"
#define TEST_ADDR6_MASK 64

#define TEST_LOOP4_STR "127.0.0.1"
#define TEST_LOOP4 IP4(127,0,0,1)
#define TEST_LOOP4_MASK 8

#define TEST_LOOP6_STR "::1"
#define TEST_LOOP6 ofp_in6addr_loopback
#define TEST_LOOP6_MASK 16

#endif /*__SOCKET_UTIL_H__*/

