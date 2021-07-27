LIB   = $(top_builddir)/lib

AM_CPPFLAGS +=  -I.
AM_CPPFLAGS +=  -I$(top_srcdir)/include/api
AM_CPPFLAGS +=  -I../common

lib_LTLIBRARIES = $(LIB)/libofp_netwrap_proc.la

__LIB__libofp_netwrap_proc_la_LDFLAGS = -shared

__LIB__libofp_netwrap_proc_la_SOURCES = app_main.c \
	 ../common/cli_arg_parse.c

