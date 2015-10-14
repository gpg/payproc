/* protocol-io.c - Server protocol helper helper functions.
 * Copyright (C) 2015 g10 Code GmbH
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
#include "protocol-io.h"

/* Maximum length of an input line.  */
#define MAX_LINELEN  2048


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


/* Store a data LINE away.  The function expects that the terminating
   linefeed has already been stripped.  Line continuation is supported
   as well as merging of headers with the same name.  This function
   may modify LINE.  DATAITEMS is a pointer to a key-value list which
   received the the data.  With FILTER set capitalize field names and
   do not allow special names.  */
static gpg_error_t
store_data_line (char *line, int filter, keyvalue_t *dataitems)
{
  char *p, *value;
  keyvalue_t kv;

  if (*line == ' ' || *line == '\t')
    {
      /* Continuation.  */
      if (!*dataitems)
        return gpg_error (GPG_ERR_PROTOCOL_VIOLATION);
      return keyvalue_append_with_nl (*dataitems, line+1);
    }

  /* A name must start with a letter.  Note that for items used only
     internally a name may start with an underscore. */
  if (filter)
    {
      capitalize_name (line);
      if (*line < 'A' || *line > 'Z')
        return gpg_error (GPG_ERR_INV_NAME);
    }

  p = strchr (line, ':');
  if (!p)
    return GPG_ERR_PROTOCOL_VIOLATION;
  *p++ = 0;
  while (*p == ' ' || *p == '\t')
    p++;
  value = p;

  for (kv = *dataitems; kv; kv = kv->next)
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
  return keyvalue_put (dataitems, line, value);
}


/* Read a protocol chunk into R_COMMAND and update DATATITEMS with
   the data item.  Return 0 on success.  Note that on error NULL is
   stored at R_command but DATAITEMS may have changed.  With FILTER
   set capitalize field names and do not allow special names. */
static gpg_error_t
read_data (estream_t stream, int filter,
           char **r_command, keyvalue_t *dataitems)
{
  gpg_error_t err;
  char *buffer = NULL;       /* Line buffer. */
  size_t buffer_size = 0;    /* Current length of buffer.  */
  ssize_t nread;
  size_t maxlen;
  size_t n;

  *r_command = NULL;

  /* Read the command line. */
  maxlen = MAX_LINELEN;
  nread = es_read_line (stream, &buffer, &buffer_size, &maxlen);
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

  *r_command = xtrystrdup (buffer);
  if (!*r_command)
    {
      err = gpg_err_code_from_syserror ();
      es_free (buffer);
      return err;
    }

  /* Read data lines and wait for the terminating empty line. */
  do
    {
      maxlen = MAX_LINELEN;
      nread = es_read_line (stream, &buffer, &buffer_size, &maxlen);
      if (nread < 0)
        {
          err = gpg_err_code_from_syserror ();
          es_free (buffer);
          log_error ("reading request failed: %s\n", gpg_strerror (err));
          xfree (*r_command);
          *r_command = NULL;
          return err;
        }
      if (!maxlen)
        {
          es_free (buffer);
          log_error ("reading request failed: %s\n", "data line too long");
          xfree (*r_command);
          *r_command = NULL;
          return GPG_ERR_TRUNCATED;
        }
      if (!nread)
        {
          es_free (buffer);
          log_error ("reading request failed: %s\n",
                     "EOF while reading data line");
          xfree (*r_command);
          *r_command = NULL;
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

      if (*buffer && *buffer != '#' )
        {
          err = store_data_line (buffer, filter, dataitems);
          if (err)
            {
              es_free (buffer);
              xfree (*r_command);
              *r_command = NULL;
              return err;
            }
        }
    }
  while (*buffer);
  es_free (buffer);

  return 0;
}


/* Read the request into R_COMMAND and update DATATITEMS with the data
   from the request.  Return 0 on success.  Note that on error NULL is
   stored at R_command but DATAITEMS may have changed.  */
gpg_error_t
protocol_read_request (estream_t stream,
                       char **r_command, keyvalue_t *dataitems)
{
  return read_data (stream, 1, r_command, dataitems);
}


/* Read the response and update DATAITEMS with the data from the
   response.  Return 0 on success.  On error an error is returned.  If
   that error has been returned by the server the description of the
   error is stored in DATAITEM under the key "_errdesc"; if the error
   is local "_errdesc" is not set.  */
gpg_error_t
protocol_read_response (estream_t stream, keyvalue_t *dataitems)
{
  gpg_error_t err, err2;
  char *status;
  const char *s;

  keyvalue_del (*dataitems, "_errdesc");
  err = read_data (stream, 0, &status, dataitems);
  if (err)
    return err;

  if (has_leading_keyword (status, "OK"))
    ;
  else if ((s = has_leading_keyword (status, "ERR")))
    {
      unsigned long n;
      char *endp;

      n = strtoul (s, &endp, 10);
      if (!n)
        err = gpg_error (GPG_ERR_PROTOCOL_VIOLATION);
      else
        {
          err = n;
          for (s = endp; *s == ' ' || *s == '\t'; s++)
            ;
          if (!*s)
            s = gpg_strerror (err);

          err2 = keyvalue_put (dataitems, "_errdesc", s);
          if (err2)
            {
              keyvalue_del (*dataitems, "_errdesc");
              err = err2;
            }
        }
    }
  else
    err = gpg_error (GPG_ERR_INV_RESPONSE);

  xfree (status);
  return err;
}
