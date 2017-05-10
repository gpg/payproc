/* t-util.c - Regression test for util.c
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
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "t-common.h"

#include "util.h" /* The module under test.  */


static void
test_keyvalue_put_meta (void)
{
  static struct { const char *string; } tests[] = {
    { "Name=Werner&Email=wk=test@gnupg.org&" },
    { "Name=" },
    { "Name=&" },
    { "Name==" },
    { "Name=&Foo=%3d%26" },
    /* Fixme: Add bad case tests.  */
    { NULL }
  };
  gpg_error_t err;
  keyvalue_t data = NULL;
  keyvalue_t kv;
  int idx;

  for (idx=0; tests[idx].string; idx++)
    {
      if (verbose)
        printf ("test %d: '%s'\n", idx, tests[idx].string);
      err = keyvalue_put_meta (&data, tests[idx].string);
      if (err)
        {
          fprintf (stderr, "test %d ('%s') failed: %s\n",
                  idx, tests[idx].string, gpg_strerror (err));
          fail (idx);
        }
      else if (verbose)
        {
          for (kv = data; kv; kv = kv->next)
            printf ("  %s: %s\n", kv->name, kv->value);
        }
      keyvalue_release (data);
      data = NULL;
    }
}


static void
do_test_base64_encoding (int idx, const char *plain, const char *encoded)
{
  gpg_error_t err;
  void *buffer;
  size_t buflen;

  buffer = base64_encode (plain, strlen (plain));
  if (!buffer)
    fail (idx);
  if (strcmp (buffer, encoded))
    fail (idx);

  err = base64_decode (encoded, &buffer, &buflen);
  if (err)
    fail (idx);
  if (!buffer)
    fail (idx);
  if (buflen != strlen (plain) || memcmp (buffer, plain, buflen))
    fail (idx);
  xfree (buffer);
}


static void
test_base64_encoding (void)
{
  static const char *test_string = "libgpg-error is free software; "
    "you can redistribute it and/or modify it under the terms of "
    "the GNU Lesser General Public License as published by the Free "
    "Software Foundation; either version 2.1 of the License, or "
    "(at your option) any later version.";

  static const char *test_b64_string = "bGliZ3BnLWVycm9yIGlzIGZyZWUgc29"
    "mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnkgaXQgd"
    "W5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgTGVzc2VyIEdlbmVyYWwgUHVibGljIEx"
    "pY2Vuc2UgYXMgcHVibGlzaGVkIGJ5IHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb"
    "247IGVpdGhlciB2ZXJzaW9uIDIuMSBvZiB0aGUgTGljZW5zZSwgb3IgKGF0IHlvdXI"
    "gb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi4=";

  do_test_base64_encoding (1, test_string, test_b64_string);
  do_test_base64_encoding (2, "",     "");
  do_test_base64_encoding (3, "a",    "YQ==");
  do_test_base64_encoding (4, "aa",   "YWE=");
  do_test_base64_encoding (5, "aaa",  "YWFh");
  do_test_base64_encoding (6, "aaaa", "YWFhYQ==");
}


static void
test_convert_amount (void)
{
  static struct
  {
    int digits;
    const char *string;
    unsigned int expected;
  } tv[] = {
    { 0, "", 0 },
    { 0, " ", 0 },
    { 0, "\t", 0 },
    { 0, "-1", 0 },
    { 2, "1.23", 123 },
    { 2, "+1.23", 123 },
    { 2, "-1.23", 0 },
    { 2, "1.2", 120 },
    { 2, "1.", 100 },
    { 2, "1", 100 },
    { 2, "20", 2000 },
    { 2, "20.01", 2001 },
    { 2, "20.09", 2009 },
    { 2, "23.59", 2359 },
    { 2, "23.50", 2350 },
    { 2, "23.5",  2350 },
    { 2, "23",    2300 },
    { 2, "23+",   0 },
    { 2, "451",    45100 },
    { 2, "451.00", 45100 },
    { 2, "451..00", 0 },
    { 2, "45.1.00", 0 },
    { 2, "4512.00", 451200 },
    { 2, "451200000000000000000000000000000000000000000000.00", 0 },
    { 3, "20", 20000 },
    { 3, "20.01", 20010 },
    { 3, "20.09", 20090 },
    { 3, "23.59", 23590 },
    { 3, "23.50", 23500 },
    { 3, "23.507",23507 },
    { 3, "23.5",  23500 },
    { 1, "20",      200 },
    { 1, "20.01",     0 },
    { 1, "20.09",     0 },
    { 1, "23.59",     0 },
    { 1, "23.50",     0 },
    { 1, "23.5",    235 },
    { 1, "23",      230 },
    { 0, "20",       20 },
    { 0, "20.01",     0 },
    { 0, "20.09",     0 },
    { 0, "23.59",     0 },
    { 0, "23.50",     0 },
    { 0, "23.5",      0 },
    { 0, "23",       23 }
  };
  int tidx;

  for (tidx=0; tidx < DIM (tv); tidx++)
    {
      unsigned int value;

      value = convert_amount (tv[tidx].string, tv[tidx].digits);
      if (value == tv[tidx].expected)
        pass ();
      else
        fail (tidx);
    }
}


int
main (int argc, char **argv)
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;

  test_keyvalue_put_meta ();
  test_base64_encoding ();
  test_convert_amount ();

  return !!errorcount;
}
