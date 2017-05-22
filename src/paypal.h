/* paypal.h - Definitions to access the paypal.com service
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

#ifndef PAYPAL_H
#define PAYPAL_H

/*-- paypal.c --*/
gpg_error_t paypal_find_create_plan (keyvalue_t *dict);
gpg_error_t paypal_create_subscription (keyvalue_t *dict);
gpg_error_t paypal_checkout_prepare (keyvalue_t *dict);
gpg_error_t paypal_checkout_execute (keyvalue_t *dict);


/*-- paypal-ipn.c --*/
void paypal_proc_ipn (keyvalue_t *dict);


#endif /*PAYPAL_H*/
