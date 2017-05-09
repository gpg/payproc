/* currency.h - Definitions for currency management functions
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

#ifndef CURRENCY_H
#define CURRENCY_H

void read_exchange_rates (void);

int valid_currency_p (const char *string, int *r_decdigits);
const char *get_currency_info (int seq, char const **r_desc, double *r_rate);
char *convert_currency (char *buffer, size_t bufsize,
                        const char *currency, const char *amount);

int valid_recur_p (const char *string, int *r_recur);


#endif /*CURRENCY_H*/
