/* preorder.h - Definition for preorder related functions
 * Copyright (C) 2015 g10 Code GmbH
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

#ifndef PREORDER_H
#define PREORDER_H

gpg_error_t preorder_store_record (keyvalue_t *dictp);
gpg_error_t preorder_update_record (keyvalue_t dict);
gpg_error_t preorder_get_record (keyvalue_t *dictp);


#endif /*PREORDER_H*/
