/* encrypt.c - Encrypt data items etc.
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
#include <gpgme.h>

#include "util.h"
#include "logging.h"
#include "payprocd.h"
#include "encrypt.h"


/* The OpenPGP key used to encrypt items in the database.  A secret
 * key is required.  NULL if not set.  */
static gpgme_key_t database_key;
/* The OpenPGP key used to encrypt data for use by the backoffice.  A
 * public key is required.  NULL if not set. */
static gpgme_key_t backoffice_key;



/* Setup the required OpenPGP keys.  Returnc NULL on success and an
 * error code on failure.  Also uses log_error on error.  Can be used
 * at anytime because it is npth_safe. */
gpg_error_t
encrypt_setup_keys (void)
{
  gpg_error_t err;
  gpg_error_t firsterr = 0;
  gpgme_ctx_t ctx = NULL;
  gpgme_key_t key = NULL;
  gpgme_key_t tmpkey;

  err = gpgme_new (&ctx);
  if (err)
    {
      log_error ("error allocating a GPGME context: %s\n", gpg_strerror (err));
      goto leave;
    }

  err = gpgme_set_protocol (ctx, GPGME_PROTOCOL_OPENPGP);
  if (err)
    {
      log_error ("error requesting the OpenPGP protocol: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  /* Fixme: Replace gpgme_get_key by regular key listing functions or
   * maybe even do a test encryption.  */

  if (opt.database_key_fpr)
    {
      err = gpgme_get_key (ctx, opt.database_key_fpr, &key, 1);
      if (!err && (!key || !key->can_encrypt || !key->secret))
        err = gpg_error (GPG_ERR_UNUSABLE_SECKEY);
      if (err)
        {
          if (!firsterr)
            firsterr = err;
          log_error ("error setting up database key '%s': %s\n",
                     opt.database_key_fpr, gpg_strerror (err));
        }
      else
        {
          tmpkey = database_key;
          database_key = key;
          key = NULL;
          gpgme_key_unref (tmpkey);
        }
    }
  else
    {
      tmpkey = database_key;
      database_key = NULL;
      gpgme_key_unref (tmpkey);
    }


  if (opt.backoffice_key_fpr)
    {
      gpgme_key_unref (key);
      key = NULL;
      err = gpgme_get_key (ctx, opt.backoffice_key_fpr, &key, 0);
      if (!err && (!key || !key->can_encrypt))
        err = gpg_error (GPG_ERR_UNUSABLE_PUBKEY);
      if (err)
        {
          if (!firsterr)
            firsterr = err;
          log_error ("error setting up backoffice key '%s': %s\n",
                     opt.backoffice_key_fpr, gpg_strerror (err));
        }
      else
        {
          tmpkey = backoffice_key;
          backoffice_key = key;
          key = NULL;
          gpgme_key_unref (tmpkey);
        }
    }
  else
    {
      tmpkey = backoffice_key;
      backoffice_key = NULL;
      gpgme_key_unref (tmpkey);
    }

 leave:
  if (firsterr)
    err = firsterr;
  gpgme_key_unref (key);
  gpgme_release (ctx);
  return err;
}


/* Release all keys.  */
void
encrypt_release_keys (void)
{
  gpgme_key_t tmpkey;

  tmpkey = database_key;
  database_key = NULL;
  gpgme_key_unref (tmpkey);

  tmpkey = backoffice_key;
  backoffice_key = NULL;
  gpgme_key_unref (tmpkey);
}


/* Print information about the available keys.  */
void
encrypt_show_keys (void)
{
  log_info ("Database key .: ");
  if (database_key && database_key->subkeys && database_key->uids)
    log_printf ("%s <%s>\n",
                database_key->subkeys->fpr, database_key->uids->address);
  else if (database_key)
    log_printf ("invalid\n");
  else
    log_printf ("none\n");

  log_info ("Backoffice key: ");
  if (backoffice_key && backoffice_key->subkeys && backoffice_key->uids)
    log_printf ("%s <%s>\n",
                backoffice_key->subkeys->fpr, backoffice_key->uids->address);
  else if (backoffice_key)
    log_printf ("invalid\n");
  else
    log_printf ("none\n");
}
