/* t-encrypt.c - Regression tests for encrypt.c
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "t-common.h"

#include "encrypt.c" /* The module under test.  */


static void
test_encrypt_string (void)
{
  gpg_error_t err;
  const char fortune[] = "Knowledge, sir, should be free to all!";
  /*                          -- Harry Mudd, "I, Mudd", stardate 4513.3*/
  char *ciphertext = NULL;
  char *plaintext = NULL;

  err = encrypt_string (&ciphertext, fortune,
                        (ENCRYPT_TO_DATABASE | ENCRYPT_TO_BACKOFFICE));
  if (err)
    {
      log_info ("test encryption failed: %s <%s>\n",
                gpg_strerror (err), gpg_strsource (err));
      fail (0);
      goto leave;
    }
  if (verbose)
    log_info ("encrypted: '%s'\n", ciphertext);

  err = decrypt_string (&plaintext, ciphertext);
  if (err)
    {
      log_info ("test decryption failed: %s <%s>\n",
                gpg_strerror (err), gpg_strsource (err));
      fail (0);
      goto leave;
    }
  if (verbose)
    log_info ("decrypted: '%s'\n", plaintext);

  if (strcmp (fortune, plaintext))
    {
      log_info ("encryption/decryption mismatch\n");
      fail (0);
    }

 leave:
  xfree (ciphertext);
  xfree (plaintext);
}


int
main (int argc, char **argv)
{
  if (argc > 1 && !strcmp (argv[1], "--verbose"))
    verbose = 1;

  if (!gpgme_check_version (NEED_GPGME_VERSION))
    log_fatal ("%s is too old (need %s, have %s)\n", "gpgme",
               NEED_GPGME_VERSION, gpgme_check_version (NULL));

  opt.database_key_fpr   = "5B83120DB1E3A65AE5A8DCF6AA43F1DCC7FED1B7";
  opt.backoffice_key_fpr = "B21DEAB4F875FB3DA42F1D1D139563682A020D0A";

  encrypt_setup_keys ();
  if (verbose)
    encrypt_show_keys ();

  test_encrypt_string ();

  encrypt_release_keys ();

  return !!errorcount;
}
