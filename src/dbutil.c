/* dbutil.c - Databse utility functions
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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sqlite3.h>

#include "util.h"
#include "logging.h"
#include "payprocd.h"
#include "membuf.h"
#include "dbutil.h"


/* Given a buffer of size DB_DATETIME_SIZE put the current time into it.  */
char *
db_datetime_now (char *buffer)
{
#if DB_DATETIME_SIZE != TIMESTAMP_SIZE + 4
# error mismatching timestamp sizes
#endif
  get_current_time (buffer);
  /* "19700101T120000" to
     "1970-01-01 12:00:00" */
  buffer[19] = 0;
  buffer[18] = buffer[14];
  buffer[17] = buffer[13];
  buffer[16] = ':';
  buffer[15] = buffer[12];
  buffer[14] = buffer[11];
  buffer[13] = ':';
  buffer[12] = buffer[10];
  buffer[11] = buffer[9];
  buffer[10] = ' ';
  buffer[9] = buffer[7];
  buffer[8] = buffer[6];
  buffer[7] = '-';
  buffer[6] = buffer[5];
  buffer[5] = buffer[4];
  buffer[4] = '-';

  return buffer;
}
