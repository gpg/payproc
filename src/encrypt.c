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



/* Create a new GPGME context for OpenPGP or print and return an
 * error.  */
static gpg_error_t
create_context (gpgme_ctx_t *r_ctx, gpgme_pinentry_mode_t pinmode)
{
  gpg_error_t err;

  *r_ctx = NULL;

  err = gpgme_new (r_ctx);
  if (err)
    {
      log_error ("error allocating a GPGME context: %s\n", gpg_strerror (err));
      return err;
    }

  err = gpgme_set_protocol (*r_ctx, GPGME_PROTOCOL_OPENPGP);
  if (err)
    {
      log_error ("error requesting the OpenPGP protocol: %s\n",
                 gpg_strerror (err));
      gpgme_release (*r_ctx);
      *r_ctx = NULL;
      return err;
    }

  err = gpgme_set_pinentry_mode (*r_ctx, pinmode);
  if (err)
    {
      log_error ("error setting pinentry mode: %s\n", gpg_strerror (err));
      gpgme_release (*r_ctx);
      *r_ctx = NULL;
      return err;
    }

  return 0;
}



/* Setup the required OpenPGP keys.  Returnc NULL on success and an
 * error code on failure.  Also uses log_error on error.  Can be used
 * at anytime because it is npth_safe. */
gpg_error_t
encrypt_setup_keys (void)
{
  gpg_error_t err;
  gpg_error_t firsterr = 0;
  gpgme_ctx_t ctx;
  gpgme_key_t key = NULL;
  gpgme_key_t tmpkey;

  err = create_context (&ctx, GPGME_PINENTRY_MODE_CANCEL);
  if (err)
    goto leave;

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


/* Encrypt STRING to the keys specified by the bitflags in ENCRYPT_TO
 * and return an allocated, base64 encoded string at RESULT.  On error
 * NULL is stored at RESULT and an error code returned.  */
gpg_error_t
encrypt_string (char **result, const char *string, int encrypt_to)
{
  gpg_error_t err;
  gpgme_ctx_t ctx;
  gpgme_data_t input = NULL;
  gpgme_data_t output = NULL;
  gpgme_key_t keys[2+1];
  int keycount = 0;
  gpgme_encrypt_result_t encres;
  gpgme_invalid_key_t invkey;
  int i;
  char *outbuffer = NULL;
  size_t outbuflen;

  *result = NULL;

  /* Check that a key is specified and allflags are known.  */
  if (!encrypt_to
      || (encrypt_to & ~(ENCRYPT_TO_DATABASE|ENCRYPT_TO_BACKOFFICE)))
    return gpg_error (GPG_ERR_INV_FLAG);

  /* No need to encrypt an empty string.  Use shortcut. */
  if (!string || !*string)
    {
      *result = xtrystrdup ("");
      return *result? 0 : gpg_error_from_syserror ();
    }

  /* No prepare the encryption.  */
  err = create_context (&ctx, GPGME_PINENTRY_MODE_CANCEL);
  if (err)
    return err;

  /* Create data objects.  */
  err = gpgme_data_new_from_mem (&input, string, strlen (string), 0);
  if (err)
    goto leave;

  err = gpgme_data_new (&output);
  if (err)
    goto leave;

  /* Encrypt.  */
  if ((encrypt_to & ENCRYPT_TO_DATABASE) && database_key)
    {
      gpgme_key_ref (database_key);
      keys[keycount++] = database_key;
    }
  if ((encrypt_to & ENCRYPT_TO_BACKOFFICE) && backoffice_key)
    {
      gpgme_key_ref (backoffice_key);
      keys[keycount++] = backoffice_key;
    }
  keys[keycount] = NULL;

  /* NB. The data items are in general small and thus it does not make
   * sense to use compression.  */
  err = gpgme_op_encrypt (ctx, keys,
                          (GPGME_ENCRYPT_ALWAYS_TRUST
                           | GPGME_ENCRYPT_NO_ENCRYPT_TO
                           | GPGME_ENCRYPT_NO_COMPRESS),
                          input, output);
  if (err)
    goto leave;
  encres = gpgme_op_encrypt_result (ctx);
  if (encres)
    {
      for (invkey = encres->invalid_recipients; invkey; invkey = invkey->next)
        {
          log_error ("encryption key '%s' was not used: %s <%s>\n",
                     invkey->fpr, gpg_strerror (invkey->reason),
                     gpg_strsource (invkey->reason));
          err = gpg_error (GPG_ERR_NO_PUBKEY);
        }
    }
  if (err)
    goto leave;

  /* Convert to Base64.  */
  outbuffer = gpgme_data_release_and_get_mem (output, &outbuflen);
  output = NULL;
  if (!outbuffer)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  *result = base64_encode (outbuffer, outbuflen);
  if (!*result)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }


 leave:
  gpgme_free (outbuffer);
  for (i=0; i < keycount; i++)
    gpgme_key_unref (keys[i]);
  gpgme_data_release (output);
  gpgme_data_release (input);
  gpgme_release (ctx);
  return err;
}


/* Decrypt an OpenPGP encrypted and Base64 encoded STRING and return
 * the plaintext as an allocated string at RESULT.  If the reult
 * contains embedded Nuls an error is returned.  On error NULL is
 * stored at RESULT and an error code returned.  Note that RESULT is
 * better freed using gpgme_free in case that on Windows the GPGME DLL
 * uses a different runtime than than payprocd.  */
gpg_error_t
decrypt_string (char **result, const char *string)
{
  gpg_error_t err;
  gpgme_ctx_t ctx;
  gpgme_data_t input = NULL;
  gpgme_data_t output = NULL;
  char *outbuffer = NULL;
  size_t outbuflen;

  *result = NULL;

  /* No need to decrypt an empty string.  Use shortcut. */
  if (!string || !*string)
    {
      *result = xtrystrdup ("");
      return *result? 0 : gpg_error_from_syserror ();
    }

  /* Put STRING into a GPGME data object.  */
  {
    void *tmpdata;
    size_t tmpdatalen;

    err = base64_decode (string, &tmpdata, &tmpdatalen);
    if (err)
      goto leave;
    err = gpgme_data_new_from_mem (&input, tmpdata, tmpdatalen, 1);
    xfree (tmpdata);
    if (err)
      goto leave;
  }

  /* Allocate a data object for the plaintext.  */
  err = gpgme_data_new (&output);
  if (err)
    goto leave;

  /* Prepare the decryption.  We expect that the secret key has no
   * passpharse set and thus we do not expect a Pinentry.  */
  err = create_context (&ctx, GPGME_PINENTRY_MODE_CANCEL);
  if (err)
    goto leave;

  /* Decrypt.  */
  err = gpgme_op_decrypt (ctx, input, output);
  if (err)
    goto leave;

  /* Get data from the output object.  */
  outbuffer = gpgme_data_release_and_get_mem (output, &outbuflen);
  output = NULL;
  if (!outbuffer)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  if (strlen (outbuffer) != outbuflen)
    {
      err = gpg_error (GPG_ERR_BOGUS_STRING);
      goto leave;
    }
  *result = outbuffer;
  outbuffer = NULL;

 leave:
  gpgme_free (outbuffer);
  gpgme_data_release (output);
  gpgme_data_release (input);
  gpgme_release (ctx);
  return err;
}
