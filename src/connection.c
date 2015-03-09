/* connection.c - Handle a client request.
 * Copyright (C) 2014, 2015 g10 Code GmbH
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
#include "payprocd.h"
#include "stripe.h"
#include "paypal.h"
#include "journal.h"
#include "session.h"
#include "currency.h"
#include "preorder.h"
#include "connection.h"

/* Maximum length of an input line.  */
#define MAX_LINELEN  2048

/* Helper macro for the cmd_ handlers.  */
#define set_error(a,b)                          \
  do {                                          \
    err = gpg_error (GPG_ERR_ ## a);            \
    conn->errdesc = (b);                        \
  } while (0)


/* Object describing a connection.  */
struct conn_s
{
  unsigned int idno;     /* Connection id for logging.  */
  int fd;                /* File descriptor for this connection.  */
  estream_t stream;      /* The corresponding stream object.  */
                         /* N.B. The stream object may only be used
                            by the connection thread.  */
  char *command;         /* The command line (malloced). */
  keyvalue_t dataitems;  /* The data items.  */
  const char *errdesc;   /* Optional description of an error.  */
};



/* Allocate a new conenction object and return it.  Returns
   NULL on error and sets ERRNO.  */
conn_t
new_connection_obj (void)
{
  static unsigned int counter;
  conn_t conn;

  conn = xtrycalloc (1, sizeof *conn);
  if (conn)
    {
      conn->idno = ++counter;
      conn->fd = -1;
    }
  return conn;
}

/* Initialize a connection object which has been alloacted with
   new_connection_obj.  FD is the file descriptor for the
   connection.  */
void
init_connection_obj (conn_t conn, int fd)
{
  conn->fd = fd;
}


/* Shutdown a connection.  This is used by asynchronous calls to tell
   the client that the request has been received and processing will
   continue.  */
void
shutdown_connection_obj (conn_t conn)
{
  if (conn->stream)
    {
      es_fclose (conn->stream);
      conn->stream = NULL;
    }
  if (conn->fd != -1)
    {
      close (conn->fd);
      conn->fd = -1;
    }
}


/* Release a connection object.  */
void
release_connection_obj (conn_t conn)
{
  if (!conn)
    return;

  shutdown_connection_obj (conn);

  xfree (conn->command);
  keyvalue_release (conn->dataitems);
  xfree (conn);
}


/* Return the file descriptor for the conenction CONN.  */
int
fd_from_connection_obj (conn_t conn)
{
  return conn->fd;
}


unsigned int
id_from_connection_obj (conn_t conn)
{
  return conn->idno;
}


/* Transform a data line name into a standard capitalized format; e.g.
   "Content-Type".  Conversion stops at the colon.  As usual we don't
   use the localized versions of ctype.h.  Parts inside of brackets
   ([]) are not changed. */
static void
capitalize_name (char *name)
{
  int first = 1;
  int bracket = 0;

  for (; *name && *name != ':'; name++)
    {
      if (bracket)
        {
          if (*name == ']')
            bracket--;
        }
      else if (*name == '[')
        bracket++;
      else if (*name == '-')
        first = 1;
      else if (first)
        {
          if (*name >= 'a' && *name <= 'z')
            *name = *name - 'a' + 'A';
          first = 0;
        }
      else if (*name >= 'A' && *name <= 'Z')
        *name = *name - 'A' + 'a';
    }
}


/* Store a data LINE away.  The fucntion expects that the terminating
   linefeed has already been stripped.  Line continuation is supported
   as well as merging of headers with the same name. This function may
   modify LINE. */
static gpg_error_t
store_data_line (conn_t conn, char *line)
{
  char *p, *value;
  keyvalue_t kv;

  if (*line == ' ' || *line == '\t')
    {
      /* Continuation.  */
      if (!conn->dataitems)
        return gpg_error (GPG_ERR_PROTOCOL_VIOLATION);
      return keyvalue_append_with_nl (conn->dataitems, line+1);
    }

  /* A name must start with a letter.  Note that for items used only
     internally a name may start with an underscore. */
  capitalize_name (line);
  if (*line < 'A' || *line > 'Z')
    return gpg_error (GPG_ERR_INV_NAME);

  p = strchr (line, ':');
  if (!p)
    return GPG_ERR_PROTOCOL_VIOLATION;
  *p++ = 0;
  while (*p == ' ' || *p == '\t')
    p++;
  value = p;

  for (kv = conn->dataitems; kv; kv = kv->next)
    if (!strcmp (kv->name, line))
      break;
  if (kv)
    {
      /* We have already seen a line with that name.  */
      /* Fixme: We should use this to allow for an array, like it is
         done by the addrutil tool.  */
      return GPG_ERR_PROTOCOL_VIOLATION;
    }

  /* Insert a new data item. */
  return keyvalue_put (&conn->dataitems, line, value);
}


/* Read the request into the CONN object.  Return 0 on success.  */
static gpg_error_t
read_request (conn_t conn)
{
  gpg_error_t err;
  char *buffer = NULL;       /* Line buffer. */
  size_t buffer_size = 0;    /* Current length of buffer.  */
  ssize_t nread;
  size_t maxlen;
  size_t n;

  /* Read the command line. */
  maxlen = MAX_LINELEN;
  nread = es_read_line (conn->stream, &buffer, &buffer_size, &maxlen);
  if (nread < 0)
    {
      err = gpg_error_from_syserror ();
      es_free (buffer);
      log_error ("reading request failed: %s\n", gpg_strerror (err));
      return err;
    }
  if (!maxlen)
    {
      es_free (buffer);
      log_error ("reading request failed: %s\n", "command line too long");
      return GPG_ERR_TRUNCATED;
    }
  if (!nread)
    {
      es_free (buffer);
      log_error ("reading request failed: %s\n",
                 "EOF while reading command line");
      return GPG_ERR_EOF;
    }
  /* Strip linefeed.  */
  n = strlen (buffer);
  if (n && buffer[n-1] == '\n')
    {
      buffer[--n] = 0;
      if (n && buffer[n-1] == '\r')
        buffer[--n] = 0;
    }

  conn->command = xtrystrdup (buffer);
  if (!conn->command)
    {
      err = gpg_err_code_from_syserror ();
      es_free (buffer);
      return err;
    }

  /* Read data lines and wait for the terminating empty line. */
  do
    {
      maxlen = MAX_LINELEN;
      nread = es_read_line (conn->stream, &buffer, &buffer_size, &maxlen);
      if (nread < 0)
        {
          err = gpg_err_code_from_syserror ();
          es_free (buffer);
          log_error ("reading request failed: %s\n", gpg_strerror (err));
          return err;
        }
      if (!maxlen)
        {
          es_free (buffer);
          log_error ("reading request failed: %s\n", "data line too long");
          return GPG_ERR_TRUNCATED;
        }
      if (!nread)
        {
          es_free (buffer);
          log_error ("reading request failed: %s\n",
                     "EOF while reading data line");
          return GPG_ERR_EOF;
        }

      /* Strip linefeed.  */
      n = strlen (buffer);
      if (n && buffer[n-1] == '\n')
        {
          buffer[--n] = 0;
          if (n && buffer[n-1] == '\r')
            buffer[--n] = 0;
        }

      if (*buffer)
        {
          err = store_data_line (conn, buffer);
          if (err)
            {
              es_free (buffer);
              return err;
            }
        }
    }
  while (*buffer);
  es_free (buffer);

  return 0;
}


static void
write_data_line (keyvalue_t kv, estream_t fp)
{
  const char *value;

  if (!kv)
    return;
  value = kv->value;
  if (!value)
    return;
  es_fputs (kv->name, fp);
  es_fputs (": ", fp);
  for ( ; *value; value++)
    {
      if (*value == '\n')
        {
          if (value[1])
            es_fputs ("\n ", fp);
        }
      else
        es_putc (*value, fp);
    }
  es_putc ('\n', fp);
}



/*
 * Helper functions.
 */

/* Check the amount given in STRING and convert it to the smallest
   currency unit.  DECDIGITS gives the number of allowed post decimal
   positions.  Return 0 on error or the converted amount.  */
static unsigned int
convert_amount (const char *string, int decdigits)
{
  const char *s;
  int ndots = 0;
  int nfrac = 0;
  unsigned int value = 0;
  unsigned int v;

  if (*string == '+')
    string++; /* Skip an optioanl leading plus sign.  */
  for (s = string; *s; s++)
    {
      if (*s == '.')
        {
          if (!decdigits)
            return 0; /* Post decimal digits are not allowed.  */
          if (++ndots > 1)
            return 0; /* Too many decimal points.  */
        }
      else if (!strchr ("0123456789", *s))
        return 0;
      else if (ndots && ++nfrac > decdigits)
        return 0; /* Too many post decimal digits.  */
      else
        {
          v = 10*value + (*s - '0');
          if (v < value)
            return 0; /* Overflow.  */
          value = v;
        }
    }

  for (; nfrac < decdigits; nfrac++)
    {
      v = 10*value;
      if (v < value)
        return 0; /* Overflow.  */
      value = v;
    }

  return value;
}


/* Return a string with the amount computed from CENTS.  DECDIGITS
   gives the number of post decimal positions in CENTS.  Return NULL
   on error.  es_free must be used to release the return value. */
static char *
reconvert_amount (int cents, int decdigits)
{
  unsigned int tens;
  int i;

  if (decdigits <= 0)
    return es_bsprintf ("%d", cents);
  else
    {
      for (tens=1, i=0; i < decdigits; i++)
        tens *= 10;
      return es_bsprintf ("%d.%0*d", cents / tens, decdigits, cents % tens);
    }
}



/* SESSION is a multipurpose command to help implement a state-full
   service.  Note that the state information is intentional not
   persistent and thus won't survive a daemon restart.

   The following sub-commands are available:

   create [TTL]

     Create a new session

     A new session is created and the provided data dictionary is
     stored by payprocd for future requests.  The data dictionary is
     optional.  On success the returned data has an "_SESSID" item
     which is to be used for all further requests.  If TTL has been
     given this is used instead of the defaul TTL value.

   destroy SESSID

     Destroy a session.

     This shall be used to free the internal storage required for the
     session and to avoid leaving sensitive information in RAM.

   get SESSID

     Get data from a session.

     Return the data stored in the session identified by SESSID.

   put SESSID

     Put data into a session.

     Store or update the given data in the session.  Deleting an item
     from the session dictionary is possible by putting an empty
     string for it.

   alias SESSID

     Create an alias for the session.

     On success the returned data has an "_ALIASID" item which is to
     be used for all further alias related requests.

   dealias ALIASID

     Destroy the given ALIAS.

     This does not destroy the session.

   sessid ALIASID

     Return the session id for an alias.

     On success the returned data has an "_SESSID" item.

 */
static gpg_error_t
cmd_session (conn_t conn, char *args)
{
  gpg_error_t err;
  keyvalue_t kv;
  char *options;
  char *sessid = NULL;
  char *aliasid = NULL;
  char *errdesc;

  if ((options = has_leading_keyword (args, "create")))
    {
      int ttl = atoi (options);
      err = session_create (ttl, conn->dataitems, &sessid);
      keyvalue_release (conn->dataitems);
      conn->dataitems = NULL;
    }
  else if ((options = has_leading_keyword (args, "get")))
    {
      keyvalue_release (conn->dataitems);
      conn->dataitems = NULL;
      err = session_get (options, &conn->dataitems);
    }
  else if ((options = has_leading_keyword (args, "put")))
    {
      err = session_put (options, conn->dataitems);
      if (gpg_err_code (err) == GPG_ERR_ENOMEM)
        {
          /* We are tight on memory - better destroy the session so
             that the caller can't try over and over again.  */
          session_destroy (options);
        }
      keyvalue_release (conn->dataitems);
      conn->dataitems = NULL;
    }
  else if ((options = has_leading_keyword (args, "destroy")))
    {
      err = session_destroy (options);
      keyvalue_release (conn->dataitems);
      conn->dataitems = NULL;
    }
  else if ((options = has_leading_keyword (args, "alias")))
    {
      err = session_create_alias (options, &aliasid);
      keyvalue_release (conn->dataitems);
      conn->dataitems = NULL;
    }
  else if ((options = has_leading_keyword (args, "dealias")))
    {
      err = session_destroy_alias (options);
      keyvalue_release (conn->dataitems);
      conn->dataitems = NULL;
    }
  else if ((options = has_leading_keyword (args, "sessid")))
    {
      keyvalue_release (conn->dataitems);
      conn->dataitems = NULL;
      err = session_get_sessid (options, &sessid);
    }
  else
    {
      es_fputs ("ERR 1 (Unknown sub-command)\n"
                "# Supported sub-commands are:\n"
                "#   create [TTL]\n"
                "#   get SESSID\n"
                "#   put SESSID\n"
                "#   destroy SESSID\n"
                "#   alias SESSID\n"
                "#   dealias ALIASID\n"
                "#   sessid ALIASID\n"
                , conn->stream);
      return 0;
    }

  switch (gpg_err_code (err))
    {
    case GPG_ERR_LIMIT_REACHED:
      errdesc = "Too many active sessions or too many aliases for a session";
      break;
    case GPG_ERR_NOT_FOUND:
      errdesc = "No such session or alias or session timed out";
      break;
    case GPG_ERR_INV_NAME:
      errdesc = "Invalid session or alias id";
      break;
    default: errdesc = NULL;
    }

  if (err)
    es_fprintf (conn->stream, "ERR %d (%s)\n",
                err, errdesc? errdesc : gpg_strerror (err));
  else
    {
      es_fprintf (conn->stream, "OK\n");
      if (sessid)
        es_fprintf (conn->stream, "_SESSID: %s\n", sessid);
      if (aliasid)
        es_fprintf (conn->stream, "_ALIASID: %s\n", aliasid);
      for (kv = conn->dataitems; kv; kv = kv->next)
        if (kv->name[0] >= 'A' && kv->name[0] < 'Z')
          write_data_line (kv, conn->stream);
    }
  xfree (sessid);
  xfree (aliasid);
  return err;
}



/* The CARDTOKEN command creates a token for a card.  The following
   values are expected in the dataitems:

   Number:     The number of the card
   Exp-Year:   The expiration year (2014..2199)
   Exp-Month:  The expiration month (1..12)
   Cvc:        The CVS number (100..9999)
   Name:       Name of the card holder (optional)

   On success these items are returned:

   Token:     The one time use token
   Last4:     The last 4 digits of the card for display
   Live:      Set to 'f' in test mode or 't' in live mode.
 */
static gpg_error_t
cmd_cardtoken (conn_t conn, char *args)
{
  gpg_error_t err;
  keyvalue_t dict = conn->dataitems;
  keyvalue_t kv;
  const char *s;
  int aint;

  (void)args;

  s = keyvalue_get_string (dict, "Number");
  if (!*s)
    {
      set_error (MISSING_VALUE, "Credit card number not given");
      goto leave;
    }

  s = keyvalue_get_string (dict, "Exp-Year");
  if (!*s || (aint = atoi (s)) < 2014 || aint > 2199 )
    {
      set_error (INV_VALUE, "Expiration year out of range");
      goto leave;
    }

  s = keyvalue_get_string (dict, "Exp-Month");
  if (!*s || (aint = atoi (s)) < 1 || aint > 12 )
    {
      set_error (INV_VALUE, "Invalid expiration month");
      goto leave;
    }

  s = keyvalue_get_string (dict, "Cvc");
  if (!*s || (aint = atoi (s)) < 100 || aint > 9999 )
    {
      set_error (INV_VALUE, "The CVC has not 2 or 4 digits");
      goto leave;
    }

  err = stripe_create_card_token (&conn->dataitems);

 leave:
  if (err)
    {
      es_fprintf (conn->stream, "ERR %d (%s)\n", err,
                  conn->errdesc? conn->errdesc : gpg_strerror (err));
      write_data_line (keyvalue_find (conn->dataitems, "failure"),
                       conn->stream);
      write_data_line (keyvalue_find (conn->dataitems, "failure-mesg"),
                       conn->stream);
    }
  else
    es_fprintf (conn->stream, "OK\n");
  for (kv = conn->dataitems; kv; kv = kv->next)
    if (kv->name[0] >= 'A' && kv->name[0] < 'Z')
      write_data_line (kv, conn->stream);

  return err;
}



/* The CHARGECARD command charges the given amount to a card.  The
   following values are expected in the dataitems:

   Amount:     The amount to charge with optional decimal fraction.
   Currency:   A 3 letter currency code (EUR, USD, GBP, JPY)
   Card-Token: The token returned by the CARDTOKEN command.
   Capture:    Optional; defaults to true.  If set to false
               this command creates only an authorization.
               The command CAPTURECHARGE must then be used
               to actually charge the card. [currently ignored]
   Desc:       Optional description of the charge.
   Stmt-Desc:  Optional string to be displayed on the credit
               card statement.  Will be truncated at about 15 characters.
   Email:      Optional contact mail address of the customer
   Meta[NAME]: Meta data further described by NAME.  This is used to convey
               application specific data to the log file.

   On success these items are returned:

   Charge-Id:  The ID describing this charge
   Live:       Set to 'f' in test mode or 't' in live mode.
   Currency:   The currency of the charge.
   Amount:     The charged amount with optional decimal fraction.
   _timestamp: The timestamp as written to the journal

 */
static gpg_error_t
cmd_chargecard (conn_t conn, char *args)
{
  gpg_error_t err;
  keyvalue_t dict = conn->dataitems;
  keyvalue_t kv;
  const char *s;
  unsigned int cents;
  int decdigs;
  char *buf = NULL;

  (void)args;

  /* Get currency and amount.  */
  s = keyvalue_get_string (dict, "Currency");
  if (!valid_currency_p (s, &decdigs))
    {
      set_error (MISSING_VALUE, "Currency missing or not supported");
      goto leave;
    }

  s = keyvalue_get_string (dict, "Amount");
  if (!*s || !(cents = convert_amount (s, decdigs)))
    {
      set_error (MISSING_VALUE, "Amount missing or invalid");
      goto leave;
    }
  err = keyvalue_putf (&conn->dataitems, "_amount", "%u", cents);
  dict = conn->dataitems;
  if (err)
    goto leave;

  /* We only support the use of a card token and no direct supply of
     card details.  This makes it easies to protect or audit the
     actual credit card data.  The token may only be used once.  */
  s = keyvalue_get_string (dict, "Card-Token");
  if (!*s)
    {
      set_error (MISSING_VALUE, "Card-Token missing");
      goto leave;
    }

  /* Let's ask Stripe to process it.  */
  err = stripe_charge_card (&conn->dataitems);
  if (err)
    goto leave;

  buf = reconvert_amount (keyvalue_get_int (conn->dataitems, "_amount"),
                          decdigs);
  if (!buf)
    {
      err = gpg_error_from_syserror ();
      conn->errdesc = "error converting _amount";
      goto leave;
    }
  err = keyvalue_put (&conn->dataitems, "Amount", buf);
  if (err)
    goto leave;
  jrnl_store_charge_record (&conn->dataitems, 1);

 leave:
  if (err)
    {
      es_fprintf (conn->stream, "ERR %d (%s)\n", err,
                  conn->errdesc? conn->errdesc : gpg_strerror (err));
      write_data_line (keyvalue_find (conn->dataitems, "failure"),
                       conn->stream);
      write_data_line (keyvalue_find (conn->dataitems, "failure-mesg"),
                       conn->stream);
    }
  else
    es_fprintf (conn->stream, "OK\n");
  for (kv = conn->dataitems; kv; kv = kv->next)
    if (kv->name[0] >= 'A' && kv->name[0] < 'Z')
      write_data_line (kv, conn->stream);
  if (!err)
    write_data_line (keyvalue_find (conn->dataitems, "_timestamp"),
                     conn->stream);
  es_free (buf);
  return err;
}



/* The PPCHECKOUT does a PayPal transaction.  Depending on the
   sub-command different data items are required.

   The following sub-commands are available:

   prepare

     Start a checkout operation.  In this mode the data is collected,
     and access code fetched from paypal and a redirect URL returned
     to the caller.  Required data:

     Amount:     The amount to charge with optional decimal fraction.
     Currency:   A 3 letter currency code (EUR, USD, GBP, JPY)
     Desc:       Optional description of the charge.
     Meta[NAME]: Meta data further described by NAME.  This is used
                 to convey application specific data to the log file.
     Return-Url: URL to which Paypal redirects.
     Cancel-Url: URL to which Paypal redirects on cancel.
     Session-Id: Id of the session to be used for storing state.  If this
                 is not given a new session will be created.
     Paypal-Xp:  An optional Paypa Experience Id.

     On success these items are returned:

     _SESSID:    If Session-Id was not supplied the id of a new session
                 is returned.
     Redirect-Url: The caller must be redirected to this URL for further
                   processing.

   execute

     Finish a Paypal checkout operation.  Required data:

     Alias-Id:     The alias id used to access the state from the
                   prepare command.  This should be retrieved from the
                   Return-Url's "aliasid" parameter which has been
                   appended to the Return-Url by the prepare sub-command.
     Paypal-Payer: Returned by Paypal via the
                   Return-Url's "PayerID" parameter.

     On success these items are returned:

     Charge-Id:  The ID describing this charge
     Live:       Set to 'f' in test mode or 't' in live mode.
     Currency:   The currency of the charge.
     Amount:     The charged amount with optional decimal fraction.
     Email:      The mail address as told by Paypal.
     _timestamp: The timestamp as written to the journal

 */
static gpg_error_t
cmd_ppcheckout (conn_t conn, char *args)
{
  gpg_error_t err;
  char *options;
  int decdigs;
  char *newsessid = NULL;
  keyvalue_t dict = conn->dataitems;
  keyvalue_t kv;
  const char *s;
  int execmode = 0;

  if ((options = has_leading_keyword (args, "prepare")))
    {
      /* Get currency and amount.  */
      s = keyvalue_get_string (dict, "Currency");
      if (!valid_currency_p (s, &decdigs))
        {
          set_error (MISSING_VALUE, "Currency missing or not supported");
          goto leave;
        }

      s = keyvalue_get_string (dict, "Amount");
      if (!*s || !convert_amount (s, decdigs))
        {
          set_error (MISSING_VALUE, "Amount missing or invalid");
          goto leave;
        }

      /* Create a session if no session-id has been supplied.  */
      s = keyvalue_get_string (dict, "Session-Id");
      if (!*s)
        {
          err = session_create (0, NULL, &newsessid);
          if (err)
            goto leave;
          err = keyvalue_put (&conn->dataitems, "Session-Id", newsessid);
          if (err)
            goto leave;
          dict = conn->dataitems;
        }

      /* Let's ask Paypal to process it.  */
      err = paypal_checkout_prepare (&conn->dataitems);
      if (err)
        goto leave;
      dict = conn->dataitems;
    }
  else if ((options = has_leading_keyword (args, "execute")))
    {
      execmode = 1;

      err = paypal_checkout_execute (&conn->dataitems);
      if (err)
        goto leave;
      dict = conn->dataitems;
      jrnl_store_charge_record (&conn->dataitems, 2);
      dict = conn->dataitems;
    }
  else
    {
      es_fputs ("ERR 1 (Unknown sub-command)\n"
                "# Supported sub-commands are:\n"
                "#   prepare\n"
                "#   execute\n"
                , conn->stream);
      return 0;
    }

 leave:
  if (err)
    {
      es_fprintf (conn->stream, "ERR %d (%s)\n", err,
                  conn->errdesc? conn->errdesc : gpg_strerror (err));
      write_data_line (keyvalue_find (conn->dataitems, "failure"),
                       conn->stream);
      write_data_line (keyvalue_find (conn->dataitems, "failure-mesg"),
                       conn->stream);
    }
  else
    {
      es_fprintf (conn->stream, "OK\n");
    }

  for (kv = conn->dataitems; kv; kv = kv->next)
    if ((!execmode && !strcmp (kv->name, "Redirect-Url"))
        || (execmode && (!strcmp (kv->name, "Charge-Id")
                          || !strcmp (kv->name, "Live")
                          || !strcmp (kv->name, "Email")
                          || !strcmp (kv->name, "Currency")
                          || !strcmp (kv->name, "Amount"))))
      write_data_line (kv, conn->stream);

  if (!err)
    {
      if (newsessid)
        es_fprintf (conn->stream, "_SESSID: %s\n", newsessid);
      write_data_line (keyvalue_find (conn->dataitems, "_timestamp"),
                       conn->stream);
    }
  xfree (newsessid);
  return err;
}



/* The SEPAPREORDER command adds a preorder record for a SEPA payment
   into the preorder database.  The following values are expected in
   the dataitems:

   Amount:     The amount to charge with optional decimal fraction.
   Currency:   If given its value must be EUR.
   Desc:       Optional description of the charge.
   Email:      Optional contact mail address of the customer
   Meta[NAME]: Meta data further described by NAME.  This is used to convey
               application specific data to the log file.

   On success these items are returned:

   SEPA-Ref:   A string to be returned to the caller.
   Amount:     The reformatted amount
   Currency:   The value "EUR"
   _timestamp: The timestamp as written to the preorder db.

 */
static gpg_error_t
cmd_sepapreorder (conn_t conn, char *args)
{
  gpg_error_t err;
  keyvalue_t dict = conn->dataitems;
  keyvalue_t kv;
  const char *s;
  unsigned int cents;
  char *buf = NULL;

  (void)args;

  /* Get currency and amount.  */
  s = keyvalue_get (dict, "Currency");
  if (!s)
    {
      err = keyvalue_put (&conn->dataitems, "Currency", "EUR");
      if (err)
        goto leave;
    }
  else if (strcasecmp (s, "EUR"))
    {
      set_error (INV_VALUE, "Currency must be \"EUR\" if given");
      goto leave;
    }

  s = keyvalue_get_string (dict, "Amount");
  if (!*s || !(cents = convert_amount (s, 2)))
    {
      set_error (MISSING_VALUE, "Amount missing or invalid");
      goto leave;
    }
  err = keyvalue_putf (&conn->dataitems, "_amount", "%u", cents);
  dict = conn->dataitems;
  if (err)
    goto leave;
  buf = reconvert_amount (keyvalue_get_int (conn->dataitems, "_amount"), 2);
  if (!buf)
    {
      err = gpg_error_from_syserror ();
      conn->errdesc = "error converting _amount";
      goto leave;
    }
  err = keyvalue_put (&conn->dataitems, "Amount", buf);
  if (err)
    goto leave;

  /* Note that the next function does not only store the record but
     also creates the SEPA-Ref value and puts it into dataitems.  This
     is to make sure SEPA-Ref is a unique key for the preorder db.  */
  err = preorder_store_record (&conn->dataitems);

 leave:
  if (err)
    {
      es_fprintf (conn->stream, "ERR %d (%s)\n", err,
                  conn->errdesc? conn->errdesc : gpg_strerror (err));
      write_data_line (keyvalue_find (conn->dataitems, "failure"),
                       conn->stream);
      write_data_line (keyvalue_find (conn->dataitems, "failure-mesg"),
                       conn->stream);
    }
  else
    es_fprintf (conn->stream, "OK\n");
  for (kv = conn->dataitems; kv; kv = kv->next)
    if (kv->name[0] >= 'A' && kv->name[0] < 'Z')
      write_data_line (kv, conn->stream);

  es_free (buf);
  return err;
}



/* The CHECKAMOUNT command checks whether a given amount is within the
   configured limits for payment.  It may eventually provide
   additional options.  The following values are expected in the
   dataitems:

   Amount:     The amount to check with optional decimal fraction.
   Currency:   A 3 letter currency code (EUR, USD, GBP, JPY)

   On success these items are returned:

   _amount:    The amount converted to an integer (i.e. 10.42 EUR -> 1042)
   Amount:     The amount as above.
   Limit:      If given, the maximum amount acceptable
   Euro:       If returned, Amount converted to Euro.

 */
static gpg_error_t
cmd_checkamount (conn_t conn, char *args)
{
  gpg_error_t err;
  keyvalue_t dict = conn->dataitems;
  keyvalue_t kv;
  const char *curr;
  const char *s;
  unsigned int cents;
  int decdigs;
  char amountbuf[AMOUNTBUF_SIZE];

  (void)args;

  /* Delete items, we want to set.  */
  keyvalue_del (conn->dataitems, "Limit");

  /* Get currency and amount.  */
  curr = keyvalue_get_string (dict, "Currency");
  if (!valid_currency_p (curr, &decdigs))
    {
      set_error (MISSING_VALUE, "Currency missing or not supported");
      goto leave;
    }

  s = keyvalue_get_string (dict, "Amount");
  if (!*s || !(cents = convert_amount (s, decdigs)))
    {
      set_error (MISSING_VALUE, "Amount missing or invalid");
      goto leave;
    }

  if (*convert_currency (amountbuf, sizeof amountbuf, curr, s))
    err = keyvalue_put (&conn->dataitems, "Euro", amountbuf);
  else
    err = 0;

  err = keyvalue_putf (&conn->dataitems, "_amount", "%u", cents);
  dict = conn->dataitems;
  if (err)
    goto leave;

 leave:
  if (err)
    {
      es_fprintf (conn->stream, "ERR %d (%s)\n", err,
                  conn->errdesc? conn->errdesc : gpg_strerror (err));
    }
  else
    {
      es_fprintf (conn->stream, "OK\n");
      write_data_line (keyvalue_find (conn->dataitems, "_amount"),
                       conn->stream);
    }
  for (kv = conn->dataitems; kv; kv = kv->next)
    if (kv->name[0] >= 'A' && kv->name[0] < 'Z')
      write_data_line (kv, conn->stream);
  return err;
}



/* GETINFO is a multipurpose command to return certain config data. It
   requires a subcommand.  See the online help for a list of
   subcommands.
 */
static gpg_error_t
cmd_getinfo (conn_t conn, char *args)
{
  int i;

  if (has_leading_keyword (args, "list-currencies"))
    {
      const char *name, *desc;
      double rate;

      es_fputs ("OK\n", conn->stream);
      for (i=0; (name = get_currency_info (i, &desc, &rate)); i++)
        es_fprintf (conn->stream, "# %s %11.4f - %s\n",
                    name, rate, desc);
    }
  else if (has_leading_keyword (args, "version"))
    {
      es_fputs ("OK " PACKAGE_VERSION "\n", conn->stream);
    }
  else if (has_leading_keyword (args, "pid"))
    {
      es_fprintf (conn->stream, "OK %u\n", (unsigned int)getpid());
    }
  else if (has_leading_keyword (args, "live"))
    {
      if (opt.livemode)
        es_fprintf (conn->stream, "OK\n");
      else
        es_fprintf (conn->stream, "ERR 179 (running in test mode)\n");
    }
  else
    {
      es_fputs ("ERR 1 (Unknown sub-command)\n"
                "# Supported sub-commands are:\n"
                "#   list-currencies    List supported currencies\n"
                "#   version            Show the version of this daemon\n"
                "#   pid                Show the pid of this process\n"
                "#   live               Returns OK if in live mode\n"
                , conn->stream);
    }

  return 0;
}


/* Process a PING command.  */
static gpg_error_t
cmd_ping (conn_t conn, char *args)
{
  if (*args)
    es_fprintf (conn->stream, "OK %s\n",args);
  else
    es_fputs ("OK pong\n", conn->stream);

  return 0;
}



/* The handler serving a connection. */
void
connection_handler (conn_t conn)
{
  gpg_error_t err;
  keyvalue_t kv;
  char *cmdargs;

  conn->stream = es_fdopen_nc (conn->fd, "r+,samethread");
  if (!conn->stream)
    {
      err = gpg_error_from_syserror ();
      log_error ("failed to open fd %d as stream: %s\n",
                 conn->fd, gpg_strerror (err));
      return;
    }

  err = read_request (conn);
  if (err)
    {
      log_error ("reading request failed: %s\n", gpg_strerror (err));
      es_fprintf (conn->stream, "ERR %u %s\n", err, gpg_strerror (err));
      return;
    }
  es_fflush (conn->stream);

  if ((cmdargs = has_leading_keyword (conn->command, "SESSION")))
    err = cmd_session (conn, cmdargs);
  else if ((cmdargs = has_leading_keyword (conn->command, "CARDTOKEN")))
    err = cmd_cardtoken (conn, cmdargs);
  else if ((cmdargs = has_leading_keyword (conn->command, "CHARGECARD")))
    err = cmd_chargecard (conn, cmdargs);
  else if ((cmdargs = has_leading_keyword (conn->command, "PPCHECKOUT")))
    err = cmd_ppcheckout (conn, cmdargs);
  else if ((cmdargs = has_leading_keyword (conn->command, "SEPAPREORDER")))
    err = cmd_sepapreorder (conn, cmdargs);
  else if ((cmdargs = has_leading_keyword (conn->command, "CHECKAMOUNT")))
    err = cmd_checkamount (conn, cmdargs);
  else if ((cmdargs = has_leading_keyword (conn->command, "PPIPNHD")))
    {
      /* This is an asynchronous call.  Thus send okay, close the
         socket, and only then process the IPN.  */
      es_fputs ("OK\n\n", conn->stream);
      shutdown_connection_obj (conn);
      paypal_proc_ipn (&conn->dataitems);
    }
  else if ((cmdargs = has_leading_keyword (conn->command, "GETINFO")))
    err = cmd_getinfo (conn, cmdargs);
  else if ((cmdargs = has_leading_keyword (conn->command, "PING")))
    err = cmd_ping (conn, cmdargs);
  else
    {
      es_fprintf (conn->stream, "ERR 1 (Unknown command)\n");
      es_fprintf (conn->stream, "_cmd: %s\n", conn->command);
      for (kv = conn->dataitems; kv; kv = kv->next)
        es_fprintf (conn->stream, "%s: %s\n", kv->name, kv->value);
    }

  if (conn->stream)
    es_fprintf (conn->stream, "\n");

}
