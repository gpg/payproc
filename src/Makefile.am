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

bin_PROGRAMS = payprocd payproc-jrnl ppipnhd
noinst_PROGRAMS = $(module_tests) t-http
noinst_LIBRARIES = libcommon.a libcommonpth.a
dist_pkglibexec_SCRIPTS = geteuroxref

TESTS = $(module_tests)

common_sources = \
	util.c util.h \
	estream.c estream.h \
	estream-printf.c estream-printf.h \
	libjnlib-config.h \
	logging.c logging.h \
	membuf.c membuf.h \
	strlist.c strlist.h \
	percent.c \
	argparse.c argparse.h

common_headers = \
	jrnl-fields.h

libcommon_a_SOURCES = $(common_sources)
libcommon_a_CFLAGS = $(AM_CFLAGS) $(LIBGPG_ERROR_CFLAGS) -DWITHOUT_NPTH=1
libcommonpth_a_SOURCES = $(common_sources)
libcommonpth_a_CFLAGS = $(AM_CFLAGS) $(LIBGPG_ERROR_CFLAGS)

utility_sources = \
	http.c http.h \
	cJSON.c cJSON.h

payprocd_SOURCES = \
	payprocd.c payprocd.h \
	connection.c connection.h \
	currency.c currency.h \
	stripe.c stripe.h \
	paypal-ipn.c paypal.h \
	tlssupport.c tlssupport.h \
	cred.c cred.h \
	journal.c journal.h \
	session.c session.h \
	$(common_headers) \
	$(utility_sources)
payprocd_CFLAGS = $(GPG_ERROR_CFLAGS) $(NPTH_CFLAGS) $(LIBGCRYPT_CFLAGS) \
                  $(LIBGNUTLS_CFLAGS)
payprocd_LDADD = -lm libcommonpth.a \
                  $(GPG_ERROR_LIBS) $(NPTH_LIBS) $(LIBGCRYPT_LIBS) \
                  $(LIBGNUTLS_LIBS)

payproc_jrnl_SOURCES = \
        payproc-jrnl.c \
	$(common_headers)

ppipnhd_SOURCES = ppipnhd.c
ppipnhd_CFLAGS =
ppipnhd_LDADD =

module_tests = t-connection

AM_CFLAGS = $(GPG_ERROR_CFLAGS)
LDADD  = -lm libcommon.a $(GPG_ERROR_LIBS)

t_common_sources = t-common.h $(utility_sources)
t_common_cflags  = $(GPG_ERROR_CFLAGS) $(NPTH_CFLAGS) $(LIBGNUTLS_CFLAGS)
t_common_ldadd   = libcommonpth.a $(GPG_ERROR_LIBS) $(NPTH_LIBS) \
                   $(LIBGNUTLS_LIBS) -lm

# (http.c and http.h are part of t_common_sources)
t_http_SOURCES = t-http.c $(t_common_sources)
t_http_CFLAGS  = $(t_common_cflags)
t_http_LDADD   = $(t_common_ldadd)

t_connection_SOURCES = t-connection.c stripe.c paypal-ipn.c \
                       journal.c session.c currency.c $(t_common_sources)
t_connection_CFLAGS  = $(t_common_cflags) $(LIBGCRYPT_CFLAGS)
t_connection_LDADD   = $(t_common_ldadd) $(LIBGCRYPT_LIBS)
