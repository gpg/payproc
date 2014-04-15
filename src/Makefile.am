# src/Makefile.am
# Copyright (C) 2014 g10 Code GmbH
#
# This file is part of Payproc.
#
# Payproc is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# Payproc is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

EXTRA_DIST = cJSON.readme tls-ca.pem


bin_PROGRAMS = payprocd

utility_sources = \
	util.c util.h \
	estream.c estream.h \
	estream-printf.c estream-printf.h \
	libjnlib-config.h \
	logging.c logging.h \
	http.c http.h \
	cJSON.c cJSON.h \
	membuf.c membuf.h \
	strlist.c strlist.h \
	argparse.c argparse.h

payprocd_SOURCES = \
	payprocd.c payprocd.h \
	connection.c connection.h \
	stripe.c stripe.h \
	tlssupport.c tlssupport.h \
	cred.c cred.h \
	journal.c journal.h \
	$(utility_sources)

noinst_PROGRAMS = $(module_tests) t-http
TESTS = $(module_tests)

module_tests = t-connection

AM_CFLAGS = $(GPG_ERROR_CFLAGS) $(NPTH_CFLAGS) $(LIBGNUTLS_CFLAGS)
LDADD  = -lm $(GPG_ERROR_LIBS) $(NPTH_LIBS) $(LIBGNUTLS_LIBS)

t_common_sources = t-common.h $(utility_sources)
t_common_cflags  = $(GPG_ERROR_CFLAGS) $(NPTH_CFLAGS) $(LIBGNUTLS_CFLAGS)
t_common_ldadd   = $(GPG_ERROR_LIBS) $(NPTH_LIBS) $(LIBGNUTLS_LIBS) -lm

# (http.c and http.h are part of common_sources)
t_http_SOURCES = t-http.c $(t_common_sources)
t_http_CFLAGS  = $(t_common_cflags)
t_http_LDADD   = $(t_common_ldadd)

t_connection_SOURCES = t-connection.c stripe.c journal.c $(t_common_sources)
t_connection_CFLAGS  = $(t_common_cflags)
t_connection_LDADD   = $(t_common_ldadd)
