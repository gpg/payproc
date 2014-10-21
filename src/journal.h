/* journal.h - Definition for journal related functions
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

#ifndef JOURNAL_H
#define JOURNAL_H

void jrnl_set_file (const char *fname);
void jrnl_store_sys_record (const char *text);
void jrnl_store_exchange_rate_record (const char *currency, double rate);
void jrnl_store_charge_record (keyvalue_t *dictp, int service);


#endif /*JOURNAL_H*/
