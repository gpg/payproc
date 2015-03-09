/* paypal.c - Access the PayPal
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
#include "cJSON.h"
#include "payprocd.h"
#include "form.h"
#include "session.h"
#include "paypal.h"


#define PAYPAL_TEST_HOST "https://api.sandbox.paypal.com"
#define PAYPAL_LIVE_HOST "https://api.paypal.com"

/* Perform a call to paypal.  KEYSTRING is the colon delimted
   concatenation of clieint_id and secret key, METHOD is the method
   without the version (e.g. "tokens") and DATA the individual part to
   be appended to the URL (e.g. a token-id).  If FORMDATA is not NULL,
   a POST operaion is used with that data instead of the default GET
   operation.  On success the function returns 0 and a status code at
   R_STATUS.  The data send with certain status code is stored in
   parsed format at R_JSON - this might be NULL.  */
static gpg_error_t
call_paypal (int bearer, const char *authstring,
             const char *method, const char *data,
             keyvalue_t kvformdata, const char *formdata,
             int *r_status, cjson_t *r_json)
{
  gpg_error_t err;
  char *url = NULL;
  http_session_t session = NULL;
  http_t http = NULL;
  unsigned int status;
  estream_t fp;

  *r_status = 0;
  *r_json = NULL;

  url = strconcat (opt.livemode? PAYPAL_LIVE_HOST : PAYPAL_TEST_HOST,
                   "/v1/", method, data? "/": NULL, data, NULL);
  if (!url)
    return gpg_error_from_syserror ();

  err = http_session_new (&session, NULL);
  if (err)
    goto leave;

  err = http_open (&http,
                   kvformdata || formdata? HTTP_REQ_POST : HTTP_REQ_GET,
                   url,
                   NULL,
                   authstring,
                   (bearer? HTTP_FLAG_AUTH_BEARER : 0),
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
  es_fprintf (fp, "Accept: application/json\r\n");

  if (kvformdata || formdata)
    {
      char *escaped;
      const char *ct;

      if (kvformdata)
        {
          err = encode_formdata (kvformdata, &escaped);
          if (err)
            goto leave;
          ct = "x-www-form-urlencoded";
        }
      else
        {
          escaped = xtrystrdup (formdata);
          if (!escaped)
            {
              err = gpg_error_from_syserror ();
              goto leave;
            }
          ct = "json";
        }

      es_fprintf (fp,
                  "Content-Type: application/%s\r\n"
                  "Content-Length: %zu\r\n", ct, strlen (escaped));
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


/* Extract the error information from JSON and put useful stuff into
   DICT.  */
static gpg_error_t
extract_error_from_json (keyvalue_t *dict, cjson_t json)
{
  gpg_error_t err;
  cjson_t j_error, j_obj;
  const char *type, *mesg;

  j_error = cJSON_GetObjectItem (json, "error");
  if (!j_error || !cjson_is_string (j_error))
    {
      log_error ("paypal: no proper error object returned\n");
      return 0; /* Ooops. */
    }
  type = j_error->valuestring;

  j_obj = cJSON_GetObjectItem (json, "error_description");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      if (j_obj)
        log_error ("paypal: error object has no proper description\n");
      mesg = "";
    }
  else
    mesg = j_obj->valuestring;

  log_info ("paypal: error: type='%s' mesg='%.100s'\n",
            type, mesg);

  err = keyvalue_put (dict, "failure", type);

  return err;
}


/* Return the URL stored under NAME in DICT and make sure that it is
   suitable.  On success 0 is returned and a malloced string with the
   URL at R_URL. */
static gpg_error_t
get_url (keyvalue_t dict, const char *name, char **r_url)
{
  const char *s;

  *r_url = NULL;
  s = keyvalue_get_string (dict, name);
  if (!*s || strchr (s, '\"'))
    return gpg_error (GPG_ERR_INV_NAME);
  *r_url = xtrystrdup (s);
  if (!*r_url)
    return gpg_error_from_syserror ();
  return 0;
}

/* Return the string stored under NAME in DICT and make sure it is not
   empty.  On success 0 is returned and a malloced copy of the string
   at R_STRING.  */
static gpg_error_t
get_string (keyvalue_t dict, const char *name, char **r_string)
{
  const char *s;

  *r_string = NULL;
  s = keyvalue_get_string (dict, name);
  if (!*s)
    return gpg_error (GPG_ERR_INV_VALUE);
  *r_string = xtrystrdup (s);
  if (!*r_string)
    return gpg_error_from_syserror ();
  return 0;
}


/* Find the approval url in JSON.  Returns NULL on error. */
static const char *
find_approval_url (cjson_t json)
{
  cjson_t j_obj, j_item, j_str;
  int i;

  j_obj = cJSON_GetObjectItem (json, "links");
  if (!j_obj || !cjson_is_array (j_obj))
    return NULL;
  for (i=0; (j_item = cJSON_GetArrayItem (j_obj, i)); i++)
    {
      j_str = cJSON_GetObjectItem (j_item, "rel");
      if (j_str && cjson_is_string (j_str)
          && !strcmp (j_str->valuestring, "approval_url"))
        {
          j_str = cJSON_GetObjectItem (j_item, "href");
          if (j_str && cjson_is_string (j_str))
            return j_str->valuestring;
        }
    }

  return NULL;
}

/* Find the sale id in JSON.  Returns NULL on error. */
static const char *
find_sale_id (cjson_t json)
{
  cjson_t j_obj, j_item, j_obj2, j_str;
  int i;

  j_obj = cJSON_GetObjectItem (json, "transactions");
  if (!j_obj || !cjson_is_array (j_obj))
    return NULL;
  for (i=0; (j_item = cJSON_GetArrayItem (j_obj, i)); i++)
    {
      j_obj2 = cJSON_GetObjectItem (j_item, "related_resources");
      if (!j_obj2 || !cjson_is_array (j_obj2))
        continue;
      j_obj = j_obj2;
      for (i=0; (j_item = cJSON_GetArrayItem (j_obj, i)); i++)
        {
          j_obj2 = cJSON_GetObjectItem (j_item, "sale");
          if (!j_obj2 || !cjson_is_object (j_obj2))
            continue;
          j_obj = j_obj2;
          j_str = cJSON_GetObjectItem (j_obj, "id");
          if (j_str && cjson_is_string (j_str))
            return j_str->valuestring;
          return NULL;
        }
    }

  return NULL;
}


/* Find the email in JSON.  Returns NULL on error. */
static const char *
find_email (cjson_t json)
{
  cjson_t j_obj;

  j_obj = cJSON_GetObjectItem (json, "payer");
  if (!j_obj || !cjson_is_object (j_obj))
    return NULL;
  j_obj = cJSON_GetObjectItem (j_obj, "payer_info");
  if (!j_obj || !cjson_is_object (j_obj))
    return NULL;
  j_obj = cJSON_GetObjectItem (j_obj, "email");
  if (!j_obj || !cjson_is_string (j_obj))
    return NULL;
  return j_obj->valuestring;
}


static gpg_error_t
copy_with_underscore (keyvalue_t *targetp, const char *name, const char *value)
{
  char namebuf[256];

  if (strlen (name) >= sizeof namebuf - 2)
    return gpg_error (GPG_ERR_TOO_LARGE);
  namebuf[0] = '_';
  strcpy (namebuf+1, name);
  return keyvalue_put (targetp, namebuf, value);
}


static gpg_error_t
copy_without_underscore (keyvalue_t *targetp,
                         const char *name, const char *value)
{
  if (strlen (name) < 2)
    return gpg_error (GPG_ERR_TOO_SHORT);
  return keyvalue_put (targetp, name+1, value);
}


/* Copy all "Meta[FOO]" fields from DICT to TARGETP but prefix them in
   TARGETP with an underscore.  */
static gpg_error_t
backup_meta (keyvalue_t *targetp, keyvalue_t dict)
{
  gpg_error_t err;
  keyvalue_t kv;

  for (kv=dict; kv; kv = kv->next)
    {
      if (!strncmp (kv->name, "Meta[", 5) && kv->value && *kv->value)
        {
          err = copy_with_underscore (targetp, kv->name, kv->value);
          if (err)
            return err;
        }
    }
  return 0;
}

/* Copy the field NAME from DICT to TARGETP but prefix it in TARGETP
   with an underscore.  */
static gpg_error_t
backup_field (keyvalue_t *targetp, keyvalue_t dict, const char *name)
{
  const char *s;

  s = keyvalue_get_string (dict, name);
  return copy_with_underscore (targetp, name, s);
}


/* Copy all "_Meta[FOO]" fields from DICT to TARGETP but remove tye
   '_' prefix.  */
static gpg_error_t
restore_meta (keyvalue_t *targetp, keyvalue_t dict)
{
  gpg_error_t err;
  keyvalue_t kv;

  for (kv=dict; kv; kv = kv->next)
    {
      if (!strncmp (kv->name, "_Meta[", 6) && kv->value && *kv->value)
        {
          err = copy_without_underscore (targetp, kv->name, kv->value);
          if (err)
            return err;
        }
    }
  return 0;
}

/* Copy the field NAME from DICT to TARGETP but remove the underscore.  */
static gpg_error_t
restore_field (keyvalue_t *targetp, keyvalue_t dict, const char *name)
{
  const char *s;

  s = keyvalue_get_string (dict, name);
  return copy_without_underscore (targetp, name, s);
}


/* The implementation of the PPCHECKOUT sub-command "prepare".  */
gpg_error_t
paypal_checkout_prepare (keyvalue_t *dict)
{
  gpg_error_t err;
  int status;
  keyvalue_t hlpdict = NULL;
  char *access_token = NULL;
  char *request = NULL;
  cjson_t json = NULL;
  cjson_t j_obj;
  char *return_url = NULL;
  char *cancel_url = NULL;
  const char *currency, *amount;
  char *desc = NULL;
  char *paypal_xp_snippet = NULL;
  const char *sessid;
  const char *s;
  char *p;
  char *aliasid = NULL;

  err = get_url (*dict, "Return-Url", &return_url);
  if (err)
    goto leave;
  err = get_url (*dict, "Cancel-Url", &cancel_url);
  if (err)
    goto leave;

  /* Currency and Amount have already been validated.  */
  currency = keyvalue_get_string (*dict, "Currency");
  amount = keyvalue_get_string (*dict, "Amount");
  /* The description is an optional input parameter and may not have
     quotes and must be less than 127 characters.  However, we need to
     provide one to Paypal. */
  s = keyvalue_get_string (*dict, "Desc");
  if (*s)
    desc = xtrystrdup (s);
  else
    desc = es_bsprintf ("Payment of %s %s", amount, currency);
  if (!desc)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  for (p=desc; *p; p++)
    if (*p == '\"')
      *p = '\'';
  if (strlen (desc) > 126)
    {
      desc[122] = ' ';
      desc[123] = '.';
      desc[124] = '.';
      desc[125] = '.';
      desc[126] = 0;
    }

  s = keyvalue_get_string (*dict, "Paypal-Xp");
  if (*s && !strchr (s, '\"'))
    paypal_xp_snippet = es_bsprintf ("  \"experience_profile_id\": \"%s\",", s);


  /* Create an alias for the session.  */
  sessid = keyvalue_get_string (*dict, "Session-Id");
  err = session_create_alias (sessid, &aliasid);
  if (err)
    goto leave;

  /* Ask for an access token.  */
  err = keyvalue_put (&hlpdict, "grant_type", "client_credentials");
  if (err)
    goto leave;

  err = call_paypal (0, opt.paypal_secret_key,
                     "oauth2/token", NULL,
                     hlpdict, NULL,
                     &status, &json);
  log_debug ("call_paypal => %s status=%d\n", gpg_strerror (err), status);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("paypal: error getting access token: status=%u\n", status);
      log_debug ("Error:\n%s\n", cJSON_Print(json));
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  /* log_debug ("Result:\n%s\n", cJSON_Print(json)); */
  j_obj = cJSON_GetObjectItem (json, "token_type");
  if (!j_obj || !cjson_is_string (j_obj)
      || strcasecmp (j_obj->valuestring, "Bearer"))
    {
      log_error ("paypal: error getting access token: bad 'token_type'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  j_obj = cJSON_GetObjectItem (json, "access_token");
  if (!j_obj || !cjson_is_string (j_obj) || !*j_obj->valuestring)
    {
      log_error ("paypal: error getting access token: bad 'access_token'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  access_token = xtrystrdup (j_obj->valuestring);
  if (!access_token)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  cJSON_Delete (json);
  json = NULL;

  /* Prepare the payment.  */
  request = es_bsprintf ("{ \"transactions\": [{"
                         "    \"amount\": {"
                         "      \"currency\":\"%s\","
                         "         \"total\":\"%s\""
                         "    },"
                         "    \"description\":\"%s\""
                         "  }],"
                         "  \"payer\": {"
                         "    \"payment_method\":\"paypal\""
                         "  },"
                         "  \"intent\":\"sale\","
                         "%s"
                         "  \"redirect_urls\": {"
                         "    \"cancel_url\":\"%s\","
                         "    \"return_url\":\"%s%caliasid=%s\""
                         "  }"
                         "}",
                         currency, amount,
                         desc,
                         paypal_xp_snippet,
                         cancel_url,
                         return_url,
                         strchr (return_url, '?')? '&' : '?',
                         aliasid);

  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = call_paypal (1, access_token,
                     "payments/payment", NULL,
                     NULL, request,
                     &status, &json);
  log_debug ("call_paypal => %s status=%d\n", gpg_strerror (err), status);
  if (err)
    goto leave;
  if (status != 200 && status != 201)
    {
      log_error ("paypal: error sending payment: status=%u\n", status);
      log_debug ("Error:\n%s\n", cJSON_Print(json));
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  /* log_debug ("Result:\n%s\n", cJSON_Print(json)); */

  /* Prepare a dictionary to collect the state.  */
  keyvalue_release (hlpdict);
  hlpdict = NULL;

  /* Get the payment id.  */
  j_obj = cJSON_GetObjectItem (json, "id");
  if (!j_obj || !cjson_is_string (j_obj) || !*j_obj->valuestring)
    {
      log_error ("paypal: payment id missing in result\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  s = j_obj->valuestring;
  err = keyvalue_put (&hlpdict, "_paypal:id", s);
  if (err)
    goto leave;

  /* Find the redirect URL and put it into the output.  */
  s = find_approval_url (json);
  if (!s)
    {
      log_error ("paypal: approval_url missing in result\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (dict, "Redirect-Url", s);
  if (err)
    goto leave;

  /* Save the state in the session.  */
  err = keyvalue_put (&hlpdict, "_paypal:access_token", access_token);
  if (err)
    goto leave;

  err = backup_meta (&hlpdict, *dict);
  if (!err)
    err = backup_field (&hlpdict, *dict, "Amount");
  if (!err)
    err = backup_field (&hlpdict, *dict, "Currency");
  if (!err)
    err = backup_field (&hlpdict, *dict, "Desc");
  if (err)
    goto leave;

  err = session_put (sessid, hlpdict);


 leave:
  xfree (request);
  xfree (access_token);
  keyvalue_release (hlpdict);
  cJSON_Delete (json);
  xfree (return_url);
  xfree (cancel_url);
  xfree (aliasid);
  xfree (paypal_xp_snippet);
  xfree (desc);
  return err;
}


/* The implementation of the PPCHECKOUT sub-command "execute".  */
gpg_error_t
paypal_checkout_execute (keyvalue_t *dict)
{
  gpg_error_t err;
  char *paypal_payer = NULL;
  const char *paypal_id;
  const char *access_token;
  char *sessid = NULL;
  keyvalue_t state = NULL;
  int status;
  cjson_t json = NULL;
  char *request = NULL;
  char *method = NULL;
  const char *s;

  err = get_string (*dict, "Paypal-Payer", &paypal_payer);
  if (err)
    goto leave;

  /* Get the state and destroy the alias so that this execute may only
     be called once.  */
  {
    const char *aliasid;

    aliasid = keyvalue_get_string (*dict, "Alias-Id");
    err = session_get_sessid (aliasid, &sessid);
    if (!err)
      err = session_destroy_alias (aliasid);
    if (!err)
      err = session_get (sessid, &state);
    if (err)
      goto leave;
  }

  /* Get the required Paypal parameters.  */
  paypal_id = keyvalue_get_string (state, "_paypal:id");
  if (!*paypal_id)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  access_token = keyvalue_get_string (state, "_paypal:access_token");
  if (!*access_token)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  /* Restore the fields from the prepare command.  */
  err = restore_meta (dict, state);
  if (!err)
    err = restore_field (dict, state, "_Amount");
  if (!err)
    err = restore_field (dict, state, "_Currency");
  if (!err)
    err = restore_field (dict, state, "_Desc");
  if (err)
    goto leave;

  /* Execute the payment.  */
  request = es_bsprintf ("{ \"payer_id\": \"%s\" }", paypal_payer);
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  method = es_bsprintf ("payments/payment/%s/execute", paypal_id);
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = call_paypal (1, access_token,
                     method, NULL,
                     NULL, request,
                     &status, &json);
  log_debug ("call_paypal => %s status=%d\n", gpg_strerror (err), status);
  if (err)
    goto leave;
  if (status != 200 && status != 201)
    {
      log_error ("paypal: error executing payment: status=%u\n", status);
      log_debug ("Error:\n%s\n", cJSON_Print(json));
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  /* log_debug ("Result:\n%s\n", cJSON_Print(json)); */

  /* Prepare return values.  */
  err = keyvalue_put (dict, "Charge-Id", paypal_id);
  if (err)
    goto leave;

  s = find_sale_id (json);
  if (!s)
    {
      log_error ("paypal: sale id missing in result\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  /* We store Paypal's sale id in Stripe's balance transaction field.  */
  err = keyvalue_put (dict, "balance-transaction", s);
  if (err)
    goto leave;

  /* If Paypal returned an Email store that; if not delete the email
     field.  */
  s = find_email (json);
  err = keyvalue_put (dict, "Email", s);
  if (err)
    goto leave;


  err = keyvalue_put (dict, "Live", opt.livemode?"t":"f");

 leave:
  cJSON_Delete (json);
  xfree (method);
  xfree (request);
  keyvalue_release (state);
  xfree (sessid);
  xfree (paypal_payer);
  return err;
}
