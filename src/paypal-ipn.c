/* paypal-ipn.c - Paypal IPN processing.
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
#include <unistd.h>

#include "util.h"
#include "logging.h"
#include "http.h"
#include "membuf.h"
#include "payprocd.h"
#include "paypal.h"


/* Perform a call to paypal.com.  KEYSTRING is the secret key, METHOD
   is the method without the version (e.g. "tokens") and DATA the
   individual part to be appended to the URL (e.g. a token-id).  If
   FORMDATA is not NULL, a POST operaion is used with that data instead
   of the default GET operation.  On success the function returns 0
   and a status code at R_STATUS.  The data send with certain status
   code is stored in parsed format at R_JSON - this might be NULL.  */
static gpg_error_t
call_verify (int live, const char *request)
{
  gpg_error_t err;
  const char *url;
  http_session_t session = NULL;
  http_t http = NULL;
  estream_t fp;
  unsigned int status;
  const char cmd[] = "cmd=_notify-validate&";
  char response[20];

  url = (live? "https://www.paypal.com/cgi-bin/webscr"
         /**/: "https://www.sandbox.paypal.com/cgi-bin/webscr");


  err = http_session_new (&session, NULL);
  if (err)
    goto leave;

  err = http_open (&http,
                   HTTP_REQ_POST,
                   url,
                   NULL,
                   NULL,
                   0,
                   NULL,
                   session,
                   NULL,
                   NULL);
  if (err)
    {
      log_error ("error accessing '%s': %s\n", url, gpg_strerror (err));
      goto leave;
    }

  fp = http_get_write_ptr (http);
  es_fprintf (fp,
              "Content-Type: application/x-www-form-urlencoded\r\n"
              "Content-Length: %zu\r\n", strlen (cmd) + strlen (request));

  http_start_data (http);
  if (es_fputs (cmd, fp))
    err = gpg_error_from_syserror ();
  else if (es_fputs (request, fp))
    err = gpg_error_from_syserror ();

  if (err)
    {
      log_error ("error sending to '%s': %s\n", url, gpg_strerror (err));
      goto leave;
    }

  err = http_wait_response (http);
  if (err)
    {
      log_error ("error reading '%s': %s\n", url, gpg_strerror (err));
      goto leave;
    }

  status = http_get_status_code (http);
  if (status != 200)
    {
      log_error ("error reading '%s': status=%03d\n", url, status);
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  if (!es_fgets (response, sizeof response, http_get_read_ptr (http)))
    {
      err = gpg_error_from_syserror ();
      log_error ("error reading '%s': %s\n", url, gpg_strerror (err));
      goto leave;
    }

  /* log_debug ("PayPal verification status '%s'\n", response); */
  err = !strcmp (response, "VERIFIED")? 0 : gpg_error (GPG_ERR_NOT_FOUND);

 leave:
  http_close (http, 0);
  http_session_release (session);
  return err;
}





/* The connection has already been shutdown but the request has been
   stored in the dictionary DICT.  We extract the original full
   request, validate it with Paypal and then do something with the
   received notification.  */
void
paypal_proc_ipn (keyvalue_t *dict)
{
  gpg_error_t err;
  keyvalue_t kv;
  char *request;
  keyvalue_t form;

  if ((kv = keyvalue_find (*dict, "Request")))
    keyvalue_remove_nl (kv);
  request = keyvalue_snatch (*dict, "Request");
  if (!request || !*request)
    {
      log_error ("ppipnhd: no request given\n");
      xfree (request);
      return;
    }

  log_info ("ppipnhd: length of request=%zu\n", strlen (request));

  /* Parse it into a dictionary.  */
  err = parse_www_form_urlencoded (&form, request);
  if (err)
    {
      log_error ("ppipnhd: error parsing request: %s\n",
                 gpg_strerror (err));
      goto leave;
    }

  for (kv = form; kv; kv = kv->next)
    log_printkeyval ("  ", kv->name, kv->value);

  /* To avoid useless verification against Paypal we first check the
     mail address.  */
  if (strcmp (keyvalue_get_string (form, "receiver_email"),
              "paypal-test@g10code.com"))
    {
      log_error ("ppipnhd: wrong receiver_email\n");
      log_printval ("  mail=", keyvalue_get_string (form, "receiver_email"));
      goto leave;
    }

  if (call_verify (!keyvalue_get_int (form, "test_ipn"), request))
    {
      log_error ("ppipnhd: IPN is not authentic\n");
      goto leave;
    }

  log_info ("ppipnhd: IPN accepted\n");

  /* Check for duplicates.  */

  /* Check status of transaction.  */


 leave:
  xfree (request);
  keyvalue_release (form);
}
