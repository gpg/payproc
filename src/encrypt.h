/* encrypt.h - Definition to encrypt data items etc.
 * Copyright (C) 2017 g10 Code GmbH
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

#ifndef ENCRYPT_H
#define ENCRYPT_H

/* Bit flags to specify which encrytpion key to use.  */
#define ENCRYPT_TO_DATABASE    1 /* Encrypt to the database.  */
#define ENCRYPT_TO_BACKOFFICE  2 /* Encrypt to the backoffice.  */

gpg_error_t encrypt_setup_keys (void);
void encrypt_release_keys (void);
void encrypt_show_keys (void);
gpg_error_t encrypt_string (char **result, const char *string, int encrypt_to);


#endif /*ENCRYPT_H*/
