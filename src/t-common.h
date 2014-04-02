/* t-common.h - Common stuff for regression tests
 * Copyright (C) 2013 g10 Code GmbH
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

#ifndef T_COMMON_H
#define T_COMMON_H

#include <stdio.h>

/* Commonly used global variables.  */
static int verbose;
static int errorcount;

/* Macros to print the result of a test.  */
#define pass()  do { ; } while(0)
#define fail(a) do {                            \
    fprintf (stderr, "%s:%d: test %d failed\n", \
             __FILE__,__LINE__, (a));           \
    errorcount++;;                              \
  } while(0)


/* Other common macros.  */
#ifndef DIM
# define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
#endif
#ifndef DIMof
# define DIMof(type,member)   DIM(((type *)0)->member)
#endif

#endif /* T_COMMON */
