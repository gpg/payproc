/* tlssupport.c - TLS supporting functions
 * Copyright (C) 2014 g10 Code GmbH
 *
 * This file is part of Payproc.
 *
 * Payproc is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * Payproc is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <gnutls/gnutls.h>


#include "util.h"
#include "logging.h"
#include "http.h"
#include "tlssupport.h"


/* This is called by the HTTP module to authenticate a connection.  */
static gpg_error_t
verify_callback (http_t hd, http_session_t session, int reserved)
{
  (void)hd;
  (void)session;
  (void)reserved;
  log_info ("verification of certificates skipped\n");
  return 0;
}


/* Initialize the TLS subsystem.  */
void
init_tls_subsystem (void)
{
  int rc;

  rc = gnutls_global_init ();
  if (rc)
    log_fatal ("gnutls_global_init failed: %s\n", gnutls_strerror (rc));

  http_register_tls_callback (verify_callback);
}

/* Deinitialize the TLS subsystem.  Thisis intended to be run from an
   atexit handler.  */
void
deinit_tls_subsystem (void)
{
  gnutls_global_deinit ();
}
