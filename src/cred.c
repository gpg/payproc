/* cred.c - Credentials support
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

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#ifdef HAVE_UCRED_H
# include <ucred.h>
#endif


#include "util.h"
#include "cred.h"


/* Retrieve the credentials from the peer using the connect file
   descriptor FD.  Returns 0 on success or -1 on error.  */
int
credentials_from_socket (int fd, pid_t *r_pid, uid_t *r_uid, gid_t *r_gid)
{
  int rc = -1;

#ifdef HAVE_SO_PEERCRED
  {
    struct ucred cr;
    socklen_t cl = sizeof cr;

    if (!getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl))
      {
         *r_pid = cr.pid;
         *r_uid = cr.uid;
         *r_gid = cr.gid;
         rc = 0;
      }
  }
#elif defined (HAVE_GETPEERUCRED)
  {
    ucred_t *ucred = NULL;

    if (getpeerucred (fd, &ucred) != -1)
      {
	*r_pid = ucred_getpid (ucred);
        *r_uid = ucred_geteuid (ucred);
        *r_gid = ucred_getegid (ucred);
        rc = 0;
	ucred_free (ucred);
      }
  }
#elif defined (HAVE_LOCAL_PEEREID)
  {
    struct unpcbid unp;
    socklen_t unpl = sizeof unp;

    if (getsockopt (fd, 0, LOCAL_PEEREID, &unp, &unpl) != -1)
      {
	*r_pid = unp.unp_pid;
	*r_uid = unp.unp_euid;
	*r_gid = unp.unp_egid;
	rc = 0;
      }
  }
#elif defined(HAVE_GETPEEREID)
  {
    if (getpeereid (fd, r_uid, r_gid) != -1)
      {
	r_pid = (pid_t)(-1);
	rc = 0;
      }
  }
#endif

  return rc;
}
