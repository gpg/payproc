/* paypal.c - Access the PayPal
 * Copyright (C) 2014, 2017 g10 Code GmbH
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
#include <npth.h>
#include <time.h>

#include "util.h"
#include "logging.h"
#include "http.h"
#include "membuf.h"
#include "cJSON.h"
#include "payprocd.h"
#include "form.h"
#include "session.h"
#include "account.h"
#include "paypal.h"


#define PAYPAL_TEST_HOST "https://api.sandbox.paypal.com"
#define PAYPAL_LIVE_HOST "https://api.paypal.com"


/* This flag is set for a 401 and used by get_access_token to flush
 * the cache.  This should never be needed so our strategy is not to
 * write restart code for a 401 but mark that so that for the next
 * access a new access token is retrieved.  */
static int status_unauthorized_seen;


/* Perform a call to paypal.  REQ_METHOD is the HTTP request method to
 * use, AUTHSTRING is the colon delimited concatenation of client_id
 * and secret key, METHOD is the method without the version
 * (e.g. "tokens") and DATA the individual part to be appended to the
 * URL (e.g. a token-id).  If FORMDATA is not NULL, a POST operaion is
 * used with that data instead of the default GET operation.  On
 * success the function returns 0 and a status code at R_STATUS.  The
 * data send with certain status code is stored in parsed format at
 * R_JSON - this might be NULL.  */
static gpg_error_t
call_paypal (http_req_t req_method, int bearer, const char *authstring,
             const char *method, const char *data,
             keyvalue_t kvformdata, const char *formdata,
             int *r_status, cjson_t *r_json)
{
  gpg_error_t err;
  const char *urlprefix;
  char *url = NULL;
  http_session_t session = NULL;
  http_t http = NULL;
  unsigned int status;
  estream_t fp;

  *r_status = 0;
  *r_json = NULL;

  if (opt.livemode)
    urlprefix = PAYPAL_LIVE_HOST "/v1/";
  else
    urlprefix = PAYPAL_TEST_HOST "/v1/";

  /* If METHOD is a complete URL with the same prefix as ours, skip
   * over it.  We do this check to make sure that we have the same
   * idea of which host to contact.  In theory the host part should be
   * case insensitive but here we assume that an HATEOAS URL uses a
   * lowercase hostname.  */
  if (!data && !strncmp (urlprefix, method, strlen (urlprefix)))
    method += strlen (urlprefix);

  url = strconcat (urlprefix, method, data? "/": NULL, data, NULL);
  if (!url)
    return gpg_error_from_syserror ();

  err = http_session_new (&session, NULL);
  if (err)
    goto leave;

  if (opt.debug_paypal)
    {
      keyvalue_t kv;
      log_debug ("paypal-req: %s %s\n",
                 req_method == HTTP_REQ_GET? "GET":
                 req_method == HTTP_REQ_HEAD? "HEAD":
                 req_method == HTTP_REQ_POST? "POST":
                 req_method == HTTP_REQ_PATCH? "PATCH": "[method?]",
                 url);
      for (kv = kvformdata; kv; kv = kv->next)
        log_printkeyval ("  ", kv->name, kv->value);
      if (formdata)
        log_printval ("          data: ", formdata);
    }

  err = http_open (&http,
                   req_method,
                   url,
                   NULL,
                   authstring,
                   ((bearer? HTTP_FLAG_AUTH_BEARER : 0)
                    | (opt.debug_paypal > 1? HTTP_FLAG_LOG_RESP : 0))
                   ,
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
  if (status == 401)
    status_unauthorized_seen = 1;

  if ((status / 100) == 2 || (status / 100) == 4 || (status / 100) == 5)
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
          cjson_t root;

          if (!*jsonstr)
            root = cJSON_Parse ("null", NULL);
          else
            root = cJSON_Parse (jsonstr, NULL);
          if (!root)
            {
              err = gpg_error_from_syserror ();
              if (opt.debug_paypal)
                log_printval ("DATA: ", jsonstr);
            }
          else
            *r_json = root;
          xfree (jsonstr);
        }
    }
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);

  if (opt.debug_paypal)
    {
      char *tmp;

      log_debug ("paypal-rsp: %3d (%s)\n", status, gpg_strerror (err));
      tmp = cJSON_Print (*r_json);
      if (tmp)
        log_printf ("%s\n", tmp);
      log_flush ();
      xfree (tmp);
    }

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

  if (dict)
    err = keyvalue_put (dict, "failure", type);
  else
    err = 0;

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


/* Find the execute URL in JSON.  Returns NULL on error. */
static const char *
find_execute_url (cjson_t json)
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
          && !strcmp (j_str->valuestring, "execute"))
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


/* Find the payer_id in JSON.  Returns NULL on error. */
static const char *
find_payer_id (cjson_t json)
{
  cjson_t j_obj;

  j_obj = cJSON_GetObjectItem (json, "payer");
  if (!j_obj || !cjson_is_object (j_obj))
    return NULL;
  j_obj = cJSON_GetObjectItem (j_obj, "payer_info");
  if (!j_obj || !cjson_is_object (j_obj))
    return NULL;
  j_obj = cJSON_GetObjectItem (j_obj, "payer_id");
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


/* Copy all "_Meta[FOO]" fields from DICT to TARGETP but remove the
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


/* Return a paypal OAUTH2 access token.  */
static gpg_error_t
get_access_token (char **r_access_token)
{
  static char *access_token;
  static time_t expires_on = 60; /* Init so that gcc does not complain
                                  * about the initial compare.  */
  static npth_mutex_t my_lock = NPTH_MUTEX_INITIALIZER;

  gpg_error_t err;
  int status;
  int max_retries = 10;
  keyvalue_t hlpdict = NULL;
  cjson_t json = NULL;
  cjson_t j_obj;
  time_t request_time, now;

  *r_access_token = NULL;

  {
    int res = npth_mutex_lock (&my_lock);
    if (res)
      log_fatal ("paypal: failed to acquire access token lock: %s\n",
                 gpg_strerror (gpg_error_from_errno (res)));
  }

  /* Hack to speed up debugging */
  /* if (!access_token) */
  /*   { */
  /*     access_token = xstrdup ("A21AAHr9LXxrE8MBBNKVdHPGrG_6PgHYY6ysPgUYGtVuttKco8uV49aPhFVR3WQ-lJdY05QENMCYKFG68cgW6wvoWVep-TLWA"); */
  /*     expires_on = time (NULL) + 3600; */
  /*   } */


 retry:
  keyvalue_release (hlpdict); hlpdict = NULL;
  cJSON_Delete (json); json = NULL;

  now = time (NULL);
  if (now == (time_t)(-1))
    {
      log_error ("time() failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      severe_error ();
    }

  /* Check whether we can use the last access token.  */
  if (!access_token)
    log_info ("paypal: cached access token: %s\n", "not yet cached");
  else if (status_unauthorized_seen)
    log_info ("paypal: cached access token: %s\n", "401 recently seen");
  else if (now + 30 < expires_on)
    {
      *r_access_token = xtrystrdup (access_token);
      if (!*r_access_token)
        err = gpg_error_from_syserror ();
      else
        err = 0; /* Success.  */
      goto leave;
    }
  else
    log_info ("paypal: cached access token: %s\n", "expire time too close");

  status_unauthorized_seen = 0;

  if (!max_retries--)
    {
      log_error ("paypal: error getting access token: too many retries\n");
      err = gpg_error (GPG_ERR_TIMEOUT);
      goto leave;
    }

  /* Ask for an access token.  */
  err = keyvalue_put (&hlpdict, "grant_type", "client_credentials");
  if (err)
    goto leave;

  request_time = time (NULL);
  if (request_time == (time_t)(-1))
    {
      log_error ("time() failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      severe_error ();
    }

  err = call_paypal (HTTP_REQ_POST, 0, opt.paypal_secret_key,
                     "oauth2/token", NULL,
                     hlpdict, NULL,
                     &status, &json);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("paypal: error getting access token: status=%u\n", status);
      err = gpg_error (GPG_ERR_EPERM);
      goto leave;
    }
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
  xfree (access_token); access_token = NULL;
  access_token = xtrystrdup (j_obj->valuestring);
  if (!access_token)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  j_obj = cJSON_GetObjectItem (json, "expires_in");
  if (!j_obj || !cjson_is_number (j_obj) || j_obj->valueint < 60)
    {
      /* We require at least 60 seconds expiration time.  */
      log_error ("paypal: error getting access token: bad 'expires_in'\n");
      err = gpg_error (GPG_ERR_INV_RESPONSE);
      goto leave;
    }
  expires_on = request_time + j_obj->valueint;
  /* Adjust a bit to give some leeway.  */
  if (j_obj->valueint > 1800)
    expires_on -= 900;
  else if (j_obj->valueint > 600)
    expires_on -= 300;

  goto retry;

 leave:
  {
    int res = npth_mutex_unlock (&my_lock);
    if (res)
      log_fatal ("paypal: failed to release access token lock: %s\n",
                 gpg_strerror (gpg_error_from_errno (res)));
  }
  keyvalue_release (hlpdict);
  cJSON_Delete (json);
  return err;
}


/* Find the id for a given plan with NAME.  ACCESS_TOKEN is the
 * access_token we will need.  On success 0 is returned and the ID of
 * the plan is stored as a malloced string at R_PLAN_ID.  If no
 * matching plan was found, 0 is returned and NULL stored at
 * R_PLAN_ID.  On error an error code is returned and also NULL stored
 * at R_PLAN_ID.
 *
 * FIXME: Add some caching.
 */
static gpg_error_t
find_plan (const char *name, const char *access_token, char **r_plan_id)
{
  gpg_error_t err;
  int status;
  const int page_size = 20; /* Maximum allowed as of 2017-05-18.  */
  int page = 0;
  char *method = NULL;
  cjson_t json = NULL;
  cjson_t j_obj, j_item, j_str;
  int idx;
  const char *my_id, *my_name, *my_upd;
  char last_update[24+1] = {0}; /* Format: "2017-05-18T15:47:05.110Z" */
  char *last_plan_id = NULL;

  *r_plan_id = NULL;

  do
    {
      es_free (method); method = NULL;
      method = es_bsprintf ("payments/billing-plans"
                            "?status=ACTIVE&page_size=%d&page=%d",
                            page_size, page);
      if (!method)
        {
          err = gpg_error_from_syserror ();
          goto leave;
        }

      cJSON_Delete (json); json = NULL;
      err = call_paypal (HTTP_REQ_GET, 1, access_token, method,
                         NULL, NULL, NULL,
                         &status, &json);
      if (err)
        goto leave;
      if (status == 204) /* No Content */
        goto leave; /* Ready: No more plans.  */
      if (status != 200)
        {
          log_error ("paypal:%s: error: status=%u\n", __func__, status);
          err = extract_error_from_json (NULL, json);
          if (!err)
            err = gpg_error (GPG_ERR_GENERAL);
          goto leave;
        }

      j_obj = cJSON_GetObjectItem (json, "plans");
      if (!j_obj || !cjson_is_array (j_obj))
        {
          log_error ("paypal:%s: error: unexpected object returned\n",
                     __func__);
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto leave;
        }

      for (idx = 0; (j_item = cJSON_GetArrayItem (j_obj, idx)); idx++)
        {
          my_id = my_name = "[?]";
          my_upd = "";
          j_str = cJSON_GetObjectItem (j_item, "id");
          if (j_str && cjson_is_string (j_str))
            {
              my_id = j_str->valuestring;
              j_str = cJSON_GetObjectItem (j_item, "name");
              if (j_str && cjson_is_string (j_str))
                my_name = j_str->valuestring;
              j_str = cJSON_GetObjectItem (j_item, "update_time");
              if (j_str && cjson_is_string (j_str))
                my_upd = j_str->valuestring;
            }
          if (opt.debug_paypal > 1)
            log_debug ("plan: id=%s name=%s upd=%s\n", my_id, my_name, my_upd);
          if (!strcmp (my_name, name))
            {
              if (strcmp (my_upd, last_update) > 0)
                {
                  strncpy (last_update, my_upd, sizeof last_update - 1);
                  last_update[sizeof last_update - 1] = 0;
                  if (!last_plan_id)
                    last_plan_id = xtrystrdup (my_id);
                  else if (strlen (last_plan_id) >= strlen (my_id))
                    strcpy (last_plan_id, my_id);
                  else
                    {
                      xfree (last_plan_id); last_plan_id = NULL;
                      last_plan_id = xtrystrdup (my_id);
                    }
                  if (!last_plan_id)
                    {
                      err = gpg_error_from_syserror ();
                      goto leave;
                    }
                }
            }
        }
      page++;
    }
  while (idx == page_size);


 leave:
  /* On success return the plan id.  */
  if (!err && last_plan_id)
    {
      *r_plan_id = last_plan_id;
      last_plan_id = NULL;
    }
  cJSON_Delete (json);
  es_free (method);
  xfree (last_plan_id);
  return err;
}


/* Using the values from DICT a corresponding plan is retrieved or
 * created.  The dictionary is then updated.  Required items:
 *
 *    Amount: The amount.
 *  Currency: A 3 letter currency code.
 *     Recur: The recurrence interval:
 *            1 = yearly, 4 = quarterly, 12 = monthly.
 *
 * On success the following items are inserted/updated:
 *
 *  _plan-name: The name of the plan.
 *    _plan-id: The PayPal plan id.
 */
gpg_error_t
paypal_find_create_plan (keyvalue_t *dict)
{
  gpg_error_t err;
  int status;
  char *access_token = NULL;
  char *request = NULL;
  cjson_t json = NULL;
  const char *s;
  cjson_t j_obj;
  char *plan_name = NULL;
  char *plan_id = NULL;
  const char *currency;
  const char *amount;
  int recur;
  const char *recur_text;

  s = keyvalue_get_string (*dict, "Currency");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  currency = s;

  recur = keyvalue_get_int (*dict, "Recur");
  if (recur == 1)
    recur_text = "yearly";
  else if (recur == 4)
    recur_text = "quarterly";
  else if (recur == 12)
    recur_text = "monthly";
  else
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  s = keyvalue_get_string (*dict, "Amount");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  amount = s;

  /* Build the name of the plan.  */
  plan_name = es_bsprintf ("gnupg-%d-%s-%s", recur, amount, currency);
  if (!plan_name)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ascii_strlwr (plan_name); /* This is for the currency part.  */
  err = keyvalue_put (dict, "_plan-name", plan_name);
  if (err)
    goto leave;

  err = get_access_token (&access_token);
  if (err)
    goto leave;

  err = find_plan (plan_name, access_token, &plan_id);
  if (err)
    goto leave;

  if (plan_id)
    {
      log_info ("found plan '%s' with id '%s'\n", plan_name, plan_id);
      goto leave;
    }

  /* No such plan - create a new one.  */
  /* I wonder why they need return URL - they are not used.  Let's
   * keep those from the example; they should be safe.  */
  request = es_bsprintf
    ("{"
     "  \"name\": \"%s\","
     "  \"description\": \"%s %s %s for gnupg\","
     "  \"type\": \"INFINITE\","
     "  \"payment_definitions\": ["
     "    {"
     "      \"name\": \"%s payment of %s %s\","
     "      \"type\": \"REGULAR\","
     "      \"frequency\": \"%s\","
     "      \"frequency_interval\": \"%d\","
     "      \"cycles\": \"0\","
     "      \"amount\": {"
     "          \"value\": \"%s\","
     "          \"currency\": \"%s\""
     "      }"
     "    }"
     "  ],"
     "  \"merchant_preferences\": {"
     "      \"auto_bill_amount\": \"NO\","
     "      \"initial_fail_amount_action\": \"CONTINUE\","
     "      \"max_fail_attempts\": \"0\","
     "      \"return_url\": \"https://www.paypal.com\","
     "      \"cancel_url\": \"http://www.paypal.com/cancel\""
     "  }"
     "}",
     plan_name, amount, currency, recur_text,
     recur_text, amount, currency,
     recur == 1? "YEAR" : "MONTH",
     recur == 4? 3 : 1,
     amount, currency
     );
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = call_paypal (HTTP_REQ_POST, 1, access_token,
                     "payments/billing-plans/", NULL,
                     NULL, request,
                     &status, &json);
  if (err)
    goto leave;
  if (status != 201)
    {
      log_error ("create_plan: error: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  /* Get the plan id.  */
  j_obj = cJSON_GetObjectItem (json, "id");
  if (!j_obj || !cjson_is_string (j_obj) || !*j_obj->valuestring)
    {
      log_error ("paypal: plan id missing in result\n");
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  plan_id = xtrystrdup (j_obj->valuestring);
  if (!plan_id)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  log_info ("paypal: new plan '%s' with id '%s' created\n", plan_name, plan_id);

  /* Need to change the state of the plan from CREATED to ACTIVE.  */
  cJSON_Delete (json); json = NULL;
  err = call_paypal (HTTP_REQ_PATCH, 1, access_token,
                     "payments/billing-plans", plan_id,
                     NULL, ("[{"
                            "    \"op\": \"replace\","
                            "    \"path\": \"/\","
                            "    \"value\": {"
                            "        \"state\": \"ACTIVE\""
                            "    }"
                            "}]"),
                     &status, &json);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("create_plan: error setting to active: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  log_info ("paypal: new plan '%s' with id '%s' activated\n",
            plan_name, plan_id);


 leave:
  if (!err && plan_id)
    err = keyvalue_put (dict, "_plan-id", plan_id);
  es_free (plan_name);
  xfree (plan_id);
  es_free (request);
  cJSON_Delete (json);
  xfree (access_token);
  return err;
}


/* The implementation of the PPCHECKOUT sub-command "prepare" for
 * recurring donations.  The exepcted value in DICT are:
 *
 *   _plan-id: The plan ID for this sunscription.
 * _plan-name: The name of the plan for this subscription.
 *      Recur: The recurrence interval
 *       Desc: An optional  description string.
 * Session-Id: Id of the session to be used for storing state.
 * Return-Url: URL to which Paypal shall redirect.
 * Cancel-Url: URL to which Paypal shall redirect on cancel.
 *
 * On success the following items are inserted/updated:
 *
 * Redirect-Url: The caller must be redirected to this URL for further
 *               processing.
 */
gpg_error_t
paypal_create_subscription (keyvalue_t *dict)
{
  gpg_error_t err;
  int status;
  keyvalue_t hlpdict = NULL;
  char *access_token = NULL;
  char *account_id = NULL;
  char *request = NULL;
  cjson_t json = NULL;
  const char *plan_id;
  const char *plan_name;
  const char *email;
  char *return_url = NULL;
  char *cancel_url = NULL;
  char *desc = NULL;
  const char *sessid;
  const char *s;
  char *p;
  char *aliasid = NULL;
  char *start_date = NULL;

  plan_id = keyvalue_get_string (*dict, "_plan-id");
  if (!*plan_id)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  plan_name = keyvalue_get_string (*dict, "_plan-name");
  if (!*plan_name)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  email = keyvalue_get_string (*dict, "Email");
  if (!*email)
    {
      log_error ("%s: missing 'Email'\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = get_url (*dict, "Return-Url", &return_url);
  if (err)
    goto leave;
  err = get_url (*dict, "Cancel-Url", &cancel_url);
  if (err)
    goto leave;
  if (!keyvalue_get_int (*dict, "Recur"))
    {
      log_error ("%s: missing 'Recur'\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  /* The description is an optional input parameter and may not have
     quotes and must be less than 127 characters.  However, we need to
     provide one to Paypal. */
  s = keyvalue_get_string (*dict, "Desc");
  if (*s)
    desc = xtrystrdup (s);
  else
    desc = es_bsprintf ("Subscription using plan %s", plan_name);
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

  /* Create an alias for the session.  */
  sessid = keyvalue_get_string (*dict, "Session-Id");
  if (!*sessid)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = session_create_alias (sessid, &aliasid);
  if (err)
    goto leave;

  /* Ask for an access token.  */
  err = get_access_token (&access_token);
  if (err)
    goto leave;

  /* Create a new empty account for the customer.  */
  err = account_new_record (&account_id);
  if (err)
    goto leave;

  /* The start_date must be on the next day.  */
  start_date = get_full_isotime (64400);
  if (!start_date)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  /* Prepare the payment.  */
  request = es_bsprintf ("{"
                         "  \"name\": \"Subscription %s (%s)\","
                         "  \"description\": \"%s\","
                         "  \"start_date\": \"%s\","
                         "  \"plan\": {"
                         "      \"id\": \"%s\""
                         "  },"
                         "  \"payer\": {"
                         "      \"payment_method\": \"paypal\","
                         "      \"payer_info\": {"
                         "          \"email\": \"%s\""
                         "      }"
                         "  },"
                         "  \"override_merchant_preferences\": {"
                         "    \"cancel_url\": \"%s\","
                         "    \"return_url\": \"%s%caliasid=%s\""
                         "  }"
                         "}",
                         plan_name, account_id,
                         desc,
                         start_date,
                         plan_id,
                         email,
                         cancel_url,
                         return_url,
                         strchr (return_url, '?')? '&' : '?', aliasid);
  if (!request)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = call_paypal (HTTP_REQ_POST, 1, access_token,
                     "payments/billing-agreements", NULL,
                     NULL, request,
                     &status, &json);
  if (err)
    goto leave;
  if (status != 200 && status != 201)
    {
      log_error ("paypal: error sending payment: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* Find the redirect URL and put it into the output.  */
  s = find_approval_url (json);
  if (!s || !*s)
    {
      log_error ("paypal: HATEOAS:approval_url missing in result\n");
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  err = keyvalue_put (dict, "Redirect-Url", s);
  if (err)
    goto leave;

  /* Save the state in the session.  */
  s = find_execute_url (json);
  if (!s || !*s)
    {
      log_error ("paypal: HATEOAS:execute missing in result\n");
      err = gpg_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  err = keyvalue_put (&hlpdict, "_paypal:hateoas:execute", s);
  if (err)
    goto leave;

  err = keyvalue_put (&hlpdict, "_paypal:plan_id", plan_id);
  if (err)
    goto leave;
  err = keyvalue_put (&hlpdict, "_paypal:plan_name", plan_name);
  if (err)
    goto leave;
  err = keyvalue_put (&hlpdict, "_paypal:access_token", access_token);
  if (err)
    goto leave;
  err = keyvalue_put (&hlpdict, "_paypal:account_id", account_id);
  if (err)
    goto leave;

  err = backup_meta (&hlpdict, *dict);
  if (!err)
    err = backup_field (&hlpdict, *dict, "Amount");
  if (!err)
    err = backup_field (&hlpdict, *dict, "Currency");
  if (!err)
    err = backup_field (&hlpdict, *dict, "Desc");
  if (!err)
    err = backup_field (&hlpdict, *dict, "Recur");
  if (err)
    goto leave;

  err = session_put (sessid, hlpdict);
  if (err)
    goto leave;


 leave:
  xfree (request);
  xfree (start_date);
  xfree (account_id);
  xfree (access_token);
  keyvalue_release (hlpdict);
  cJSON_Delete (json);
  xfree (return_url);
  xfree (cancel_url);
  xfree (aliasid);
  xfree (desc);
  return err;
}


/* The implementation of the PPCHECKOUT sub-command "prepare".  This
 * is not used for recurring donations.  */
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
  if (!*sessid)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = session_create_alias (sessid, &aliasid);
  if (err)
    goto leave;

  /* Ask for an access token.  */
  err = get_access_token (&access_token);
  if (err)
    goto leave;

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

  err = call_paypal (HTTP_REQ_POST, 1, access_token,
                     "payments/payment", NULL,
                     NULL, request,
                     &status, &json);
  if (err)
    goto leave;
  if (status != 200 && status != 201)
    {
      log_error ("paypal: error sending payment: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* Prepare a dictionary to collect the state.  */

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
  const char *hateoas_execute;
  const char *paypal_id;
  const char *access_token;
  const char *account_id = NULL;
  char *sessid = NULL;
  keyvalue_t state = NULL;
  int status;
  cjson_t json = NULL;
  char *request = NULL;
  char *method = NULL;
  const char *s;
  keyvalue_t accountdict = NULL;

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

  /* Get the required Paypal parameters.  We first try the HATEOAS
   * approach and then fallback to the old id thing.  */
  hateoas_execute = keyvalue_get (state, "_paypal:hateoas:execute");
  if (!hateoas_execute)
    {
      paypal_id = keyvalue_get_string (state, "_paypal:id");
      if (!*paypal_id)
        {
          err = gpg_error (GPG_ERR_MISSING_VALUE);
          goto leave;
        }

      account_id = NULL;
    }
  else
    {
      paypal_id = NULL;
      account_id = keyvalue_get_string (state, "_paypal:account_id");
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
  if (!err)
    err = restore_field (dict, state, "_Recur");
  if (err)
    goto leave;

  /* Execute the payment.  */
  if (hateoas_execute)  /* The modern method.  */
    {
      /* Note that we need to send some empty payload.  */
      err = call_paypal (HTTP_REQ_POST, 1, access_token,
                         hateoas_execute, NULL,
                         NULL, "{ }",
                         &status, &json);
    }
  else /* The old method.  */
    {
      err = get_string (*dict, "Paypal-Payer", &paypal_payer);
      if (err)
        goto leave;

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

      err = call_paypal (HTTP_REQ_POST, 1, access_token,
                         method, NULL,
                         NULL, request,
                         &status, &json);
    }
  if (err)
    goto leave;
  if (status != 200 && status != 201)
    {
      log_error ("paypal: error executing payment: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* Prepare return values.  */
  if (hateoas_execute)  /* The modern method.  */
    {
      cjson_t j_obj;

      j_obj = cJSON_GetObjectItem (json, "id");
      if (!j_obj || !cjson_is_string (j_obj) || !*j_obj->valuestring)
        {
          log_error ("paypal: subscription id missing in result\n");
          err = gpg_error (GPG_ERR_INV_OBJ);
          goto leave;
        }
      err = keyvalue_put (dict, "Charge-Id", j_obj->valuestring);
      if (err)
        goto leave;
      err = keyvalue_del (*dict, "balance-transaction");
      if (err)
        goto leave;
    }
  else /* The old method.  */
    {
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
      /* We store Paypal's sale id in Stripe's balance
       * transaction field.  */
      err = keyvalue_put (dict, "balance-transaction", s);
      if (err)
        goto leave;
    }

  /* If Paypal returned an Email address store/update that; if not
   * delete the email field.  */
  s = find_email (json);
  err = keyvalue_put (dict, "Email", s);
  if (err)
    goto leave;

  /* If this is a subscription we have an account id item - update the
   * account database.  */
  if (account_id)
    {
      err = keyvalue_put (&accountdict, "Email", s);
      if (err)
        goto leave;
      err = keyvalue_put (&accountdict, "account-id", account_id);
      if (err)
        goto leave;
      s = find_payer_id (json);
      err = keyvalue_put (&accountdict, "_paypal_payer_id", s);
      if (err)
        goto leave;
      err = account_update_record (accountdict);
      if (err)
        goto leave;

      /* Also return that value.  */
      err = keyvalue_put (dict, "account-id", account_id);
      if (err)
        goto leave;
    }

  err = keyvalue_put (dict, "Live", opt.livemode?"t":"f");

 leave:
  cJSON_Delete (json);
  xfree (method);
  xfree (request);
  keyvalue_release (state);
  keyvalue_release (accountdict);
  xfree (sessid);
  xfree (paypal_payer);
  return err;
}
