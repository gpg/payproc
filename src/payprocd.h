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


/* The global options.  */
struct
{
  int verbose;   /* Verbose logging.  */
  int nodetach;  /* Do not detach from the console.  */

  int livemode;  /* Expect to be in live mode.  Default is test mode.  */
  char *stripe_secret_key;  /* The secret key for stripe.com */
  char *paypal_secret_key;  /* The secret key for PayPal */

} opt;



#endif /*PAYPROCD_H*/
