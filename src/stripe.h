/* stripe.h - Definitions to access the strip.com service
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

#ifndef STRIPE_H
#define STRIPE_H

gpg_error_t stripe_create_card_token (keyvalue_t dict, keyvalue_t *r_result);
gpg_error_t stripe_charge_card (keyvalue_t dict, keyvalue_t *r_result);


#endif /*STRIPE_H*/
