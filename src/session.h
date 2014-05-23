/* session.h - Definition for session management
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

#ifndef SESSION_H
#define SESSION_H

struct session_s;
typedef struct session_s *session_t;

void session_housekeeping (void);

gpg_error_t session_create (int ttl, keyvalue_t data, char **r_sessid);
gpg_error_t session_destroy (const char *sessid);
gpg_error_t session_put (const char *sessid, keyvalue_t dict);
gpg_error_t session_get (const char *sessid, keyvalue_t *dictp);


#endif /*SESSION_H*/
