/* libjnlib-config.h - local configuration of the jnlib functions
 *	Copyright (C) 2000, 2001, 2006 Free Software Foundation, Inc.
 *
 * This file is part of JNLIB, which is a subsystem of GnuPG.
 *
 * JNLIB is free software; you can redistribute it and/or modify it
 * under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * JNLIB is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copies of the GNU General Public License
 * and the GNU Lesser General Public License along with this program;
 * if not, see <http://www.gnu.org/licenses/>.
 */

/****************
 * This header is to be included only by the files in this directory
 * it should not be used by other modules.
 */

#ifndef LIBJNLIB_CONFIG_H
#define LIBJNLIB_CONFIG_H

#include "logging.h"

/* Gettext stubs.  */
#define _(a) (a)
#define N_(a) (a)

/* Malloc functions to be used by jnlib.  */
#define jnlib_malloc(a)     xtrymalloc ((a))
#define jnlib_calloc(a,b)   xtrycalloc ((a), (b))
#define jnlib_realloc(a,b)  xtryrealloc((a), (b))
#define jnlib_strdup(a)     xtrystrdup ((a))
#define jnlib_xmalloc(a)    xmalloc ((a))
#define jnlib_xcalloc(a,b)  xcalloc ((a), (b))
#define jnlib_xrealloc(a,n) xrealloc ((a), (n))
#define jnlib_xstrdup(a)    xstrdup ((a))
#define jnlib_free(a)	    xfree ((a))

/* Logging functions to be used by jnlib.  */
#define jnlib_log_debug    log_debug
#define jnlib_log_info	   log_info
#define jnlib_log_error    log_error
#define jnlib_log_fatal    log_fatal
#define jnlib_log_bug	   log_bug

/* Wrapper to set ERRNO.  */
#define jnlib_set_errno(e)  do { errno = (e); } while (0)

/* Dummy replacement for getenv.  */
#ifndef HAVE_GETENV
#define getenv(a)  (NULL)
#endif

#endif /*LIBJNUTIL_CONFIG_H*/
