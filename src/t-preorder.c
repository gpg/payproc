/* t-preorder.c - Regression test for parts of preorder.c
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <string.h>
#include <assert.h>

#include "t-common.h"

#include "preorder.c" /* The module under test.  */


static void
test_make_sepa_ref (void)
{
  char buffer[9];
  int i;

  for (i=0; i < 500; i++)
    {
      make_sepa_ref (buffer, sizeof buffer);
      if (verbose)
        printf ("%s\n", buffer);
    }
}


int
main (int argc, char **argv)
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;

  test_make_sepa_ref ();

  return !!errorcount;
}
