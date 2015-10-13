/* commands.h - Definitions pertaining to a connection.
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

#ifndef COMMANDS_H
#define COMMANDS_H

struct conn_s;
typedef struct conn_s *conn_t;


/*-- commands.c --*/
conn_t new_connection_obj (void);
void init_connection_obj (conn_t conn, int fd);
void release_connection_obj (conn_t conn);
unsigned int id_from_connection_obj (conn_t conn);
int fd_from_connection_obj (conn_t conn);

void connection_handler (conn_t conn);


#endif /*COMMANDS_H*/
