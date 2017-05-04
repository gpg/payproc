/* payprocd.h - Declarations for payprocd
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

#ifndef PAYPROCD_H
#define PAYPROCD_H

#include <sys/types.h>


/* The global options.  */
struct
{
  int verbose;   /* Verbose logging.  */
  int nodetach;  /* Do not detach from the console.  */

  int livemode;  /* Expect to be in live mode.  Default is test mode.  */
  char *stripe_secret_key;  /* The secret key for stripe.com */
  char *paypal_secret_key;  /* The secret key for PayPal */

  /* The fingerprint of the OpenPGP key used to encrypt items in the
   * database.  A secret and a public key is required.  */
  char *database_key_fpr;
  /* The fingerprint of the OpenPGP key used to encrypt data for use
   * by the backoffice.  Only the public key is required.  */
  char *backoffice_key_fpr;

  /* The count and the list of clients allowed to use the service.  */
  int n_allowed_uids;
  uid_t allowed_uids[20];

  /* The count and the list of clients allowed to use admin services.  */
  int n_allowed_admin_uids;
  uid_t allowed_admin_uids[20];

} opt;


const char *server_socket_name (void);

void shutdown_server (void);


#endif /*PAYPROCD_H*/
