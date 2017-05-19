/* stripe.c - Access the stripe.com service
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


#include "util.h"
#include "logging.h"
#include "http.h"
#include "membuf.h"
#include "cJSON.h"
#include "payprocd.h"
#include "form.h"
#include "account.h"
#include "stripe.h"


#define STRIPE_HOST "https://api.stripe.com"


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

  if (opt.debug_stripe)
    log_debug ("stripe-req: %s %s\n", formdata? "POST" : "GET", url);

  err = http_open (&http,
                   formdata? HTTP_REQ_POST : HTTP_REQ_GET,
                   url,
                   NULL,
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
          cjson_t root;

          if (!*jsonstr)
            root = cJSON_Parse ("null", NULL);
          else
            root = cJSON_Parse (jsonstr, NULL);
          if (!root)
            err = gpg_error_from_syserror ();
          else
            *r_json = root;
          xfree (jsonstr);
        }
    }
  else
    err = gpg_error (GPG_ERR_NOT_FOUND);

  if (opt.debug_stripe)
    {
      char *tmp;

      log_debug ("stripe-rsp: %3d (%s)", status, gpg_strerror (err));
      tmp = cJSON_Print (*r_json);
      if (tmp)
        log_printf ("\n%s\n", tmp);
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
  const char *type, *mesg, *code;

  j_error = cJSON_GetObjectItem (json, "error");
  if (!j_error || !cjson_is_object (j_error))
    {
      log_error ("stripe: no proper error object returned\n");
      return 0; /* Ooops. */
    }

  j_obj = cJSON_GetObjectItem (j_error, "type");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      log_error ("stripe: error object has no 'type'\n");
      return 0; /* Ooops. */
    }
  type = j_obj->valuestring;

  j_obj = cJSON_GetObjectItem (j_error, "message");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      if (j_obj)
        log_error ("stripe: error object has no proper 'message'\n");
      mesg = "";
    }
  else
    mesg = j_obj->valuestring;

  j_obj = cJSON_GetObjectItem (j_error, "code");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      if (j_obj)
        log_error ("stripe: error object has no proper 'code'\n");
      code = "";
    }
  else
    code = j_obj->valuestring;

  log_info ("stripe: error: type='%s' code='%s' mesg='%.100s'\n",
            type, code, mesg);

  if (!strcmp (type, "invalid_request_error"))
    {
      err = keyvalue_put (dict, "failure", "invalid request to stripe");
    }
  else if (!strcmp (type, "api_error"))
    {
      err = keyvalue_put (dict, "failure", "bad request to stripe");
    }
  else if (!strcmp (type, "card_error"))
    {
      err = keyvalue_put (dict, "failure", *code? code : "card error");
      if (!err && *mesg)
        err = keyvalue_put (dict, "failure-mesg", mesg);
    }
  else
    {
      log_error ("stripe: unknown type '%s' in error object\n", type);
      err = keyvalue_put (dict, "failure", "unknown error");
    }

  return err;
}


/* The implementation of CARDTOKEN.  */
gpg_error_t
stripe_create_card_token (keyvalue_t *dict)
{
  gpg_error_t err;
  int status;
  keyvalue_t query = NULL;
  cjson_t json = NULL;
  const char *s;
  int aint;
  cjson_t j_id, j_livemode, j_card, j_last4;

  s = keyvalue_get_string (*dict, "Number");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "card[number]", s);
  if (err)
    goto leave;
  keyvalue_del (*dict, "Number");

  s = keyvalue_get_string (*dict, "Exp-Year");
  if (!*s || (aint = atoi (s)) < 2014 || aint > 2199 )
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  err = keyvalue_putf (&query, "card[exp_year]", "%d", aint);
  if (err)
    goto leave;
  keyvalue_del (*dict, "Exp-Year");

  s = keyvalue_get_string (*dict, "Exp-Month");
  if (!*s || (aint = atoi (s)) < 1 || aint > 12 )
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  err = keyvalue_putf (&query, "card[exp_month]", "%d", aint);
  if (err)
    goto leave;
  keyvalue_del (*dict, "Exp-Month");

  s = keyvalue_get_string (*dict, "Cvc");
  if (!*s || (aint = atoi (s)) < 100 || aint > 9999 )
    {
      err = gpg_error (GPG_ERR_INV_VALUE);
      goto leave;
    }
  err = keyvalue_putf (&query, "card[cvc]", "%d", aint);
  if (err)
    goto leave;
  keyvalue_del (*dict, "Cvc");

  s = keyvalue_get_string (*dict, "Name");
  if (*s)
    {
      err = keyvalue_put (&query, "card[name]", s);
      if (err)
        goto leave;
    }


  err = call_stripe (opt.stripe_secret_key,
                     "tokens", NULL, query, &status, &json);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("create_card_token: error: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
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

  err = keyvalue_put (dict, "Live", cjson_is_true (j_livemode)?"t":"f");
  if (!err)
    err = keyvalue_put (dict, "Last4", j_last4->valuestring);
  if (!err)
    err = keyvalue_put (dict, "Token", j_id->valuestring);

 leave:
  keyvalue_release (query);
  cJSON_Delete (json);
  return err;
}


/* The implementation of CHARGECARD.  */
gpg_error_t
stripe_charge_card (keyvalue_t *dict)
{
  gpg_error_t err;
  int status;
  keyvalue_t query = NULL;
  cjson_t json = NULL;
  const char *s;
  cjson_t j_obj, j_tmp;

  s = keyvalue_get_string (*dict, "Currency");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "currency", s);
  if (err)
    goto leave;

  /* _amount is the amount in the smallest unit of the currency.  */
  s = keyvalue_get_string (*dict, "_amount");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "amount", s);
  if (err)
    goto leave;

  s = keyvalue_get_string (*dict, "Card-Token");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&query, "card", s);
  if (err)
    goto leave;
  keyvalue_del (*dict, "Card-Token");

  s = keyvalue_get_string (*dict, "Desc");
  if (*s)
    {
      err = keyvalue_put (&query, "description", s);
      if (err)
        goto leave;
    }

  s = keyvalue_get_string (*dict, "Stmt-Desc");
  if (*s)
    {
      err = keyvalue_put (&query, "statement_description", s);
      if (err)
        goto leave;
    }


  err = call_stripe (opt.stripe_secret_key,
                     "charges", NULL, query, &status, &json);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("charge_card: error: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
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
  err = keyvalue_put (dict, "Charge-Id", j_obj->valuestring);
  if (err)
    goto leave;

  j_obj = cJSON_GetObjectItem (json, "balance_transaction");
  err = keyvalue_put (dict, "balance-transaction",
                      ((j_obj && cjson_is_string (j_obj))?
                       j_obj->valuestring : NULL));
  if (err)
    goto leave;

  j_obj = cJSON_GetObjectItem (json, "livemode");
  if (!j_obj || !(cjson_is_boolean (j_obj)))
    {
      log_error ("charge_card: bad or missing 'livemode'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (dict, "Live", cjson_is_true (j_obj)?"t":"f");
  if (err)
    goto leave;

  j_obj = cJSON_GetObjectItem (json, "currency");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      log_error ("charge_card: bad or missing 'currency'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (dict, "Currency", j_obj->valuestring);
  if (err)
    goto leave;

  j_obj = cJSON_GetObjectItem (json, "amount");
  if (!j_obj || !cjson_is_number (j_obj))
    {
      log_error ("charge_card: bad or missing 'amount'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_putf (dict, "_amount", "%d", j_obj->valueint);
  if (err)
    goto leave;

  j_tmp = cJSON_GetObjectItem (json, "card");
  j_obj = j_tmp? cJSON_GetObjectItem (j_tmp, "last4") : NULL;
  err = keyvalue_put (dict, "Last4", ((j_obj && cjson_is_string (j_obj))?
                                        j_obj->valuestring : NULL));
  if (err)
    goto leave;


 leave:
  keyvalue_release (query);
  cJSON_Delete (json);
  return err;
}



/* Using the values from DICT a corresponding plan is retrieved or
 * created.  The dictionary is then updated.  Required items:
 *
 *   _amount: The cent based amount.
 *  Currency: A 3 letter currency code.
 *     Recur: The recurrence interval:
 *            1 = yearly, 4 = quarterly, 12 = monthly.
 * Stmt-Desc: String to be displayed on the credit card statement.
 *            Will be truncated at about 22 characters.  A suffix
 *            with the donation interval is appended.
 *
 * On success the following items are inserted/updated:
 *
 *  _plan-id: The Stripe plan id.  This is computed from the other
 *            information given
 */
gpg_error_t
stripe_find_create_plan (keyvalue_t *dict)
{
  gpg_error_t err;
  int status;
  keyvalue_t request = NULL;
  cjson_t json = NULL;
  const char *s;
  cjson_t j_obj;
  int recur;
  char *plan_id = NULL;
  char *stmt_desc = NULL;

  s = keyvalue_get_string (*dict, "Currency");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&request, "currency", s);
  if (err)
    goto leave;

  recur = keyvalue_get_int (*dict, "Recur");
  if (recur != 1 && recur != 4 && recur != 12)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }

  /* _amount is the amount in the smallest unit of the currency.  */
  s = keyvalue_get_string (*dict, "_amount");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&request, "amount", s);
  if (err)
    goto leave;

  /* Build the id.  */
  plan_id = es_bsprintf ("gnupg-%d-%s-%s", recur, s,
                         keyvalue_get_string (request, "currency"));
  if (!plan_id)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  ascii_strlwr (plan_id); /* This is for the currency part.  */


  err = call_stripe (opt.stripe_secret_key,
                     "plans", plan_id, NULL, &status, &json);
  if (err)
    goto leave;
  if (status == 200)
    {
      /* This plan already exists.  */
      goto plan_found;
    }
  else if (status != 404)
    {
      log_error ("rerteive_plan: error: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* This is a 404 - We assume that the plan was not found.  */

  err = keyvalue_put (&request, "id", plan_id);
  if (err)
    goto leave;

  if (recur == 12)
    {
      err = keyvalue_put (&request, "interval", "month");
      if (!err)
        err = keyvalue_put (&request, "interval_count", "1");
    }
  else if (recur == 4)
    {
      err = keyvalue_put (&request, "interval", "month");
      if (!err)
        err = keyvalue_put (&request, "interval_count", "3");
    }
  else
    {
      err = keyvalue_put (&request, "interval", "year");
      if (!err)
        err = keyvalue_put (&request, "interval_count", "1");
    }

  if (err)
    goto leave;


  s = keyvalue_get_string (*dict, "Stmt-Desc");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  stmt_desc = es_bsprintf ("%s%s",
                          recur == 1  ? "Yearly " :
                          recur == 4  ? "Quarterly " :
                          recur == 12 ? "Monthly " : "",
                          s);
  if (!stmt_desc)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }

  err = keyvalue_put (&request, "name", stmt_desc);
  if (err)
    goto leave;

  if (strlen (stmt_desc) > 22)
    stmt_desc[22] = 0;
  err = keyvalue_put (&request, "statement_descriptor", stmt_desc);
  if (err)
    goto leave;

  err = call_stripe (opt.stripe_secret_key,
                     "plans", NULL, request, &status, &json);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("create_plan: error: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

 plan_found:
  j_obj = cJSON_GetObjectItem (json, "id");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      log_error ("charge_card: bad or missing 'id'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (dict, "_plan-id", j_obj->valuestring);
  if (err)
    goto leave;


 leave:
  es_free (stmt_desc);
  es_free (plan_id);
  keyvalue_release (request);
  cJSON_Delete (json);
  return err;
}



/* Using the values from DICT find or create a new customer and
 * subscribe it to a provided plan.  Required items:
 *
 *   _plan_id: The plan to subscribe the customer to.
 * Card-Token: The token returned by the CARDTOKEN command.
 *
 * On success the following items are inserted/updated:
 *
 * account-id: Our account ID for the Stripe customer.
 */
gpg_error_t
stripe_create_subscription (keyvalue_t *dict)
{
  gpg_error_t err;
  int status;
  keyvalue_t request = NULL;
  keyvalue_t accountdict = NULL;
  cjson_t json = NULL;
  const char *s;
  cjson_t j_obj;
  char *customer_id = NULL; /* The Stripe customer id.  */
  char *account_id = NULL;  /* Our account id. */

  /* First check that we have all required data. */
  s = keyvalue_get_string (*dict, "_plan-id");
  if (!*s)
    {
      log_error ("%s: missing '_plan-id'\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  s = keyvalue_get_string (*dict, "Card-Token");
  if (!*s)
    {
      log_error ("%s: missing 'Card-Token'\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  s = keyvalue_get_string (*dict, "Email");
  if (!*s)
    {
      log_error ("%s: missing 'Email'\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&request, "email", s);
  if (err)
    goto leave;

  /* FIXME: Figure out whether we already have a customer with the a
   * verified mail address and print a warning that a subscription
   * already exists and can be changed using the account manager.  */

  /* Create a new empty account for the customer.  This data is also
   * stored in Stripe's metadata item.  */
  err = account_new_record (&account_id);
  if (err)
    goto leave;
  err = keyvalue_put (&request, "metadata[account_id]", account_id);
  if (err)
    goto leave;

  /* Create a customer.  */
  err = call_stripe (opt.stripe_secret_key,
                     "customers", NULL, request, &status, &json);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("create_customer: error: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  /* Get the customer ID and put it right away into the request.  */
  j_obj = cJSON_GetObjectItem (json, "id");
  if (!j_obj || !cjson_is_string (j_obj))
    {
      log_error ("create_customer: bad or missing 'id'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  customer_id = xtrystrdup (j_obj->valuestring);
  if (!customer_id)
    {
      err = gpg_error_from_syserror ();
      goto leave;
    }
  /* We don't need the result anymore.  */
  cJSON_Delete (json);
  json = NULL;

  /* Create the subscription.  */

  /* Remove the email from the request.  */
  keyvalue_del (request, "email");

  /* Put the customer into the request.  */
  err = keyvalue_put (&request, "customer", customer_id);
  if (err)
    goto leave;

  /* Add the token to the request and then delete it from the
   * dictionary.  It is supposed to be one-time and we do not want to
   * accidently use it again.  */
  s = keyvalue_get_string (*dict, "Card-Token");
  if (!*s)
    {
      log_error ("%s: missing 'Card-Token'\n", __func__);
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&request, "source", s);
  if (err)
    goto leave;
  keyvalue_del (*dict, "Card-Token");

  /* Add the plan to the request.  */
  s = keyvalue_get_string (*dict, "_plan-id");
  if (!*s)
    {
      err = gpg_error (GPG_ERR_MISSING_VALUE);
      goto leave;
    }
  err = keyvalue_put (&request, "plan", s);
  if (err)
    goto leave;

  err = call_stripe (opt.stripe_secret_key,
                     "subscriptions", NULL, request, &status, &json);
  if (err)
    goto leave;
  if (status != 200)
    {
      log_error ("create_subscriptions: error: status=%u\n", status);
      err = extract_error_from_json (dict, json);
      if (!err)
        err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }

  j_obj = cJSON_GetObjectItem (json, "livemode");
  if (!j_obj || !(cjson_is_boolean (j_obj)))
    {
      log_error ("create_subscription: bad or missing 'livemode'\n");
      err = gpg_error (GPG_ERR_GENERAL);
      goto leave;
    }
  err = keyvalue_put (dict, "Live", cjson_is_true (j_obj)?"t":"f");
  if (err)
    goto leave;

  /* Add our account id to the result.  */
  err = keyvalue_put (dict, "account-id", account_id);
  if (err)
    goto leave;

  err = keyvalue_put (&accountdict, "account-id", account_id);
  if (err)
    goto leave;
  err = keyvalue_put (&accountdict, "_stripe_cus", customer_id);
  if (err)
    goto leave;
  if ((s = keyvalue_get (*dict, "Email")))
    {
      err = keyvalue_put (&accountdict, "Email", s);
      if (err)
        goto leave;
    }
  err = account_update_record (accountdict);
  if (err)
    goto leave;


 leave:
  xfree (account_id);
  xfree (customer_id);
  keyvalue_release (accountdict);
  keyvalue_release (request);
  cJSON_Delete (json);
  return err;
}
