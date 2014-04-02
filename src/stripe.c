/* stripe.c - Access the stripe.com service
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
#include "estream.h"
#include "http.h"
#include "membuf.h"
#include "cJSON.h"
#include "payprocd.h"
#include "stripe.h"


#define STRIPE_HOST "https://api.stripe.com"


/* Encode the data in FORM for use with POST.  */
gpg_error_t
encode_formdata (keyvalue_t form, char **r_encoded)
{
  gpg_error_t err;
  membuf_t mb;
  keyvalue_t kv;
  char *escaped;

  *r_encoded = NULL;

  init_membuf (&mb, 0);
  for (kv = form; kv; kv = kv->next)
    {
      if (kv != form)
        put_membuf_str (&mb, "&");
      escaped = http_escape_string (kv->name, NULL/*form-encoding*/);
      if (!escaped)
        {
          err = gpg_error_from_syserror ();
          xfree (get_membuf (&mb, NULL));
          return err;
        }
      put_membuf_str (&mb, escaped);
      xfree (escaped);
      put_membuf_str (&mb, "=");
      escaped = http_escape_string (kv->value, NULL/*form-encoding*/);
      if (!escaped)
        {
          err = gpg_error_from_syserror ();
          xfree (get_membuf (&mb, NULL));
          return err;
        }
      put_membuf_str (&mb, escaped);
      xfree (escaped);
    }

  put_membuf (&mb, "", 1);
  *r_encoded = get_membuf (&mb, NULL);
  if (!*r_encoded)
    return gpg_error_from_syserror ();
  return 0;
}


/* Perform a call to stripe.com.  KEYSTRING is the secret key, METHOD
   is the method without the version (e.g. "tokens") and DATA the
   individual part to be appended to the URL (e.g. a token-id).  If
   FORMDATA is not NULL, a POST operaion is used with that data instead
   of the default GET operation.  On success the function returns 0
   and a status code at R_STATUS.  The data send with certain status
   code is stored in parsed format at R_JSON - this might be NULL.  */
static gpg_error_t
call_stripe (const char *keystring, const char *method, const char *data,
             keyvalue_t formdata, int *r_status, cjson_t *r_json)
{
  gpg_error_t err;
  char *url = NULL;
  http_session_t session = NULL;
  http_t http = NULL;
  unsigned int status;

  *r_status = 0;
  *r_json = NULL;

  url = strconcat (STRIPE_HOST, "/v1/", method, data? "/": NULL, data, NULL);
  if (!url)
    return gpg_error_from_syserror ();

  err = http_session_new (&session, NULL);
  if (err)
    goto leave;


  err = http_open (&http,
                   formdata? HTTP_REQ_POST : HTTP_REQ_GET,
                   url,
                   keystring,
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

  if (formdata)
    {
      estream_t fp = http_get_write_ptr (http);
      char *escaped;

      err = encode_formdata (formdata, &escaped);
      if (err)
        goto leave;

      log_debug ("formdata: '%s'\n", escaped);

      es_fprintf (fp,
                  "Content-Type: application/x-www-form-urlencoded\r\n"
                  "Content-Length: %zu\r\n", strlen (escaped));
      http_start_data (http);
      if (es_fputs (escaped, fp))
        err = gpg_error_from_syserror ();
      xfree (escaped);
    }

  err = http_wait_response (http);
  if (err)
    {
      log_error ("error reading '%s': %s\n", url, gpg_strerror (err));
      goto leave;
    }

  status = http_get_status_code (http);
  log_info ("get '%s' status=%u\n", url, status);
  *r_status = status;
  if ((status / 100) == 2 || (status / 100) == 4)
    {
      int c;
      membuf_t mb;
      char *jsonstr;

      init_membuf (&mb, 1024);
      while ((c = es_getc (http_get_read_ptr (http))) != EOF)
        put_membuf_chr (&mb, c);
      put_membuf_chr (&mb, 0);
      jsonstr = get_membuf (&mb, NULL);
      if (!jsonstr)
        err = gpg_error_from_syserror ();
      else
        {
          cjson_t root = cJSON_Parse (jsonstr, NULL);
          if (!root)
            err = gpg_error_from_syserror ();
          else
            *r_json = root;
          xfree (jsonstr);
        }
    }
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);

 leave:
  http_close (http, 0);
  http_session_release (session);
  xfree (url);
  return err;
}


/* The implementation of CARDTOKEN.  */
gpg_error_t
stripe_create_card_token (keyvalue_t dict, keyvalue_t *r_result)
{
  gpg_error_t err;
  int status;
  keyvalue_t query = NULL;
  cjson_t json = NULL;
  const char *s;
  int aint;
  cjson_t j_id, j_livemode, j_card, j_last4;

  *r_result = NULL;

  s = keyvalue_get_string (dict, "Number");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "card[number]", s);
  if (err)
    goto leave;

  s = keyvalue_get_string (dict, "Exp-Year");
  if (!*s || (aint = atoi (s)) < 2014 || aint > 2199 )
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  err = keyvalue_putf (&query, "card[exp_year]", "%d", aint);
  if (err)
    goto leave;

  s = keyvalue_get_string (dict, "Exp-Month");
  if (!*s || (aint = atoi (s)) < 1 || aint > 12 )
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  err = keyvalue_putf (&query, "card[exp_month]", "%d", aint);
  if (err)
    goto leave;

  s = keyvalue_get_string (dict, "Cvc");
  if (!*s || (aint = atoi (s)) < 100 || aint > 9999 )
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  err = keyvalue_putf (&query, "card[cvc]", "%d", aint);
  if (err)
    goto leave;

  s = keyvalue_get_string (dict, "Name");
  if (*s)
    {
      err = keyvalue_put (&query, "card[name]", s);
      if (err)
        goto leave;
    }


  err = call_stripe (opt.stripe_secret_key,
                     "tokens", NULL, query, &status, &json);
  log_debug ("call_stripe => %s status=%d\n", gpg_strerror (err), status);
  if (!err)
    log_debug ("Result:\n%s\n", cJSON_Print(json));
  if (status != 200)
    {
      log_error ("create_card_token: error: status=%u\n", status);
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  j_id = cJSON_GetObjectItem (json, "id");
  if (!j_id || !cjson_is_string (j_id))
    {
      log_error ("create_card_token: bad or missing 'id'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  j_livemode = cJSON_GetObjectItem (json, "livemode");
  if (!j_livemode || !(cjson_is_boolean (j_livemode)))
    {
      log_error ("create_card_token: bad or missing 'livemode'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  j_card = cJSON_GetObjectItem (json, "card");
  j_last4 = j_card? cJSON_GetObjectItem (j_card, "last4") : NULL;
  if (!j_last4 || !cjson_is_string (j_last4))
    {
      log_error ("create_card_token: bad or missing 'card/last4'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  err = keyvalue_put (r_result, "Live", cjson_is_true (j_livemode)?"t":"f");
  if (!err)
    err = keyvalue_put (r_result, "Last4", j_last4->valuestring);
  if (!err)
    err = keyvalue_put (r_result, "Token", j_id->valuestring);

 leave:
  keyvalue_release (query);
  cJSON_Delete (json);
  return err;
}


/* The implementation of CHARGECARD.  */
gpg_error_t
stripe_charge_card (keyvalue_t dict, keyvalue_t *r_result)
{
  gpg_error_t err;
  int status;
  keyvalue_t query = NULL;
  cjson_t json = NULL;
  const char *s;
  cjson_t j_obj;

  *r_result = NULL;

  s = keyvalue_get_string (dict, "Currency");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "currency", s);
  if (err)
    goto leave;

  /* _amount is the amount in the smallest unit of the currency.  */
  s = keyvalue_get_string (dict, "_amount");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "amount", s);
  if (err)
    goto leave;

  s = keyvalue_get_string (dict, "Card-Token");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "card", s);
  if (err)
    goto leave;

  s = keyvalue_get_string (dict, "Desc");
  if (*s)
    {
      err = keyvalue_put (&query, "description", s);
      if (err)
        goto leave;
    }

  s = keyvalue_get_string (dict, "Stmt-Desc");
  if (*s)
    {
      err = keyvalue_put (&query, "statement_description", s);
      if (err)
        goto leave;
    }


  err = call_stripe (opt.stripe_secret_key,
                     "charges", NULL, query, &status, &json);
  log_debug ("call_stripe => %s status=%d\n", gpg_strerror (err), status);
  if (!err)
    log_debug ("Result:\n%s\n", cJSON_Print(json));
  if (status != 200)
    {
      log_error ("charge_card: error: status=%u\n", status);
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  j_obj = cJSON_GetObjectItem (json, "id");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      log_error ("charge_card: bad or missing 'id'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (r_result, "Charge-Id", j_obj->valuestring);
  if (err)
    goto leave;

  j_obj = cJSON_GetObjectItem (json, "livemode");
  if (!j_obj || !(cjson_is_boolean (j_obj)))
    {
      log_error ("charge_card: bad or missing 'livemode'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (r_result, "Live", cjson_is_true (j_obj)?"t":"f");
  if (err)
    goto leave;

  j_obj = cJSON_GetObjectItem (json, "currency");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      log_error ("charge_card: bad or missing 'currency'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (r_result, "Currency", j_obj->valuestring);
  if (err)
    goto leave;

  j_obj = cJSON_GetObjectItem (json, "amount");
  if (!j_obj || !cjson_is_number (j_obj))
    {
      log_error ("charge_card: bad or missing 'amount'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_putf (r_result, "_amount", "%d", j_obj->valueint);
  if (err)
    goto leave;

 leave:
  keyvalue_release (query);
  cJSON_Delete (json);
  return err;
}
