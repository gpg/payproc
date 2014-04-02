/* connection.c - Handle a conenction.
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
#include "payprocd.h"
#include "stripe.h"
#include "connection.h"

/* Maximum length of an input line.  */
#define MAX_LINELEN  2048


/* Object describing a connection.  */
struct conn_s
{
  int fd;                /* File descriptor for this connection.  */
  estream_t stream;      /* The corresponding stream object.  */
  char *command;         /* The command line (malloced). */
  keyvalue_t dataitems;  /* The data items.  */
};




/* Allocate a new conenction object and return it.  Returns
   NULL on error and sets ERRNO.  */
conn_t
new_connection_obj (void)
{
  return xtrycalloc (1, sizeof (struct conn_s));
}

/* Initialize a connection object which has been alloacted with
   new_connection_obj.  FD is the file descriptor for the
   connection.  */
void
init_connection_obj (conn_t conn, int fd)
{
  conn->fd = fd;
}


/* Release a connection object.  */
void
release_connection_obj (conn_t conn)
{
  if (!conn)
    return;

  es_fclose (conn->stream);
  if (conn->fd != -1)
    close (conn->fd);

  xfree (conn->command);
  keyvalue_release (conn->dataitems);
  xfree (conn);
}


/* Transform a data line name into a standard capitalized format; e.g.
   "Content-Type".  Conversion stops at the colon.  As usual we don't
   use the localized versions of ctype.h. */
static void
capitalize_name (char *name)
{
  int first = 1;

  for (; *name && *name != ':'; name++)
    {
      if (*name == '-')
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
        return GPG_ERR_PROTOCOL_VIOLATION;
      return keyvalue_append_to_last (conn->dataitems, line);
    }

  capitalize_name (line);
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

  log_debug ("recvd cmd: '%s'\n", buffer);
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

      log_debug ("recvd dat: '%s'\n", buffer);
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


/* The CARDTOKEN command creates a token for a card.  The follwing
   values are expected in the dataitems:

   Number:     The number of the card
   Exp-Year:   The expiration year (2014..2199)
   Exp-Month:  The expiration month (1..12)
   Cvc:        The CVS number (100..9999)
   Name:       Name of the card holder (optional)

   On success these items are returned:

   Token:     The once time use token
   Last4:     The last 4 digits of the card for display
   Live:      f in test mode, t in live mode.

 */
static gpg_error_t
cmd_cardtoken (conn_t conn, char *args)
{
  gpg_error_t err;
  keyvalue_t result = NULL;
  keyvalue_t kv;

  (void)args;

  err = stripe_create_card_token (conn->dataitems, &result);

  if (err)
    es_fprintf (conn->stream, "ERR %d (%s)\n", err, gpg_strerror (err));
  else
    es_fprintf (conn->stream, "OK\n");
  for (kv = result; kv; kv = kv->next)
    es_fprintf (conn->stream, "%s: %s\n", kv->name, kv->value);
  keyvalue_release (result);

  return err;
}


/* The handler serving a connection.  */
void
connection_handler (conn_t conn)
{
  gpg_error_t err;
  keyvalue_t kv;
  char *cmdargs;

  conn->stream = es_fdopen_nc (conn->fd, "r+");
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

  if ((cmdargs = has_leading_keyword (conn->command, "CARDTOKEN")))
    err = cmd_cardtoken (conn, cmdargs);
  else
    {
      es_fprintf (conn->stream, "ERR 1 (Unknown command)\n");
      es_fprintf (conn->stream, "CMD: '%s'\n", conn->command);
      for (kv = conn->dataitems; kv; kv = kv->next)
        es_fprintf (conn->stream, "%s: %s\n", kv->name, kv->value);
    }
  es_fprintf (conn->stream, "\n");

}
