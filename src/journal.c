/* journal.c - Write journal file
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

/* The journal file is written with one line per transaction.  Thus a
   line may be arbitrary long.  The fields of the records are
   delimited with colons and percent escaping is used.  Percent
   escaping has the advantage that unescaping can be done in-place and
   it is well defined.  Backslash escaping would be more complex to
   handle and won't allow for easy spitting into fields (e.g. using
   cut(1)).  This tool is for a Unix system and thus we only use a LF
   as record (line) terminating character.  To allow for structured
   fields, the content of such a structured field consist of key-value
   pairs delimited by an ampersand (like HTTP form data).

   Current definition of the journal:

   | No | Name     | Description                                    |
   |----+----------+------------------------------------------------|
   |  1 | date     | UTC the record was created (yyyymmddThhmmss)   |
   |  2 | type     | Record type                                    |
   |    |          | - := sync mark record                          |
   |    |          | $ := system record                             |
   |    |          | C := credit card charge                        |
   |    |          | R := credit card refund                        |
   |  3 | live     | 1 if this is not a test account                |
   |  4 | currency | 3 letter ISO code for the currency (lowercase) |
   |  5 | amount   | Amount with decimal point                      |
   |  6 | desc     | Description for this transaction               |
   |  7 | mail     | Email address                                  |
   |  8 | meta     | Structured field with additional data          |
   |  9 | last4    | The last 4 digits of the card                  |
   | 10 | service  | Payment service (0=n/a, 1=stripe.com)          |
   | 11 | account  | Account number                                 |
   | 12 | chargeid | Charge id                                      |
   | 13 | txid     | Transaction id                                 |
   | 14 | rtxid    | Reference txid (e.g. for refunds)              |
   | 15 | euro     | amount converted to Euro                       |
   |----+----------+------------------------------------------------|

   Because of the multithreaded operation it may happen that records
   are not properly sorted by date.  To avoid problems with log file
   rotating a new log file is created for each day.

   This is a simple log which does not account for potential crashes
   or disk full conditions.  Thus it is possible that a record for a
   fully charged transaction was not written to disk.  The remedy for
   this would be the use of an extra record written right before a
   Stripe transaction.  However, this is for now too much overhead.
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <npth.h>

#include "util.h"
#include "logging.h"
#include "estream.h"
#include "payprocd.h"
#include "http.h"
#include "currency.h"
#include "journal.h"

/* The size of our standard timestamp.  */
#define TIMESTAMP_SIZE 15


/* Info about an open log file.  */
struct logfile_s
{
  char *basename;  /* The base name of the file.  */
  char *fullname;  /* The full name of the file.  */
  FILE *fp;
  char suffix[8+1];
} logfile;
static npth_mutex_t logfile_lock = NPTH_MUTEX_INITIALIZER;


/* A severe error was encountered.  Stop the process as sson as
   possible but first give other connections a chance to
   terminate.  */
static void
severe_error (void)
{
  /* FIXME: stop only this thread and wait for other threads.  */
  exit (4);
}


/* Write the log to the log file.  */
static void
write_log (const char *buffer)
{
  int res;

  if (!logfile.basename)
    return;  /* Journal not enabled.  */

  res = npth_mutex_lock (&logfile_lock);
  if (res)
    log_fatal ("failed to acquire journal writing lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));


  if (!logfile.fp || strncmp (logfile.suffix, buffer, 8))
    {
      if (logfile.fp && fclose (logfile.fp))
        {
          log_error ("error closing '%s': %s\n",
                     logfile.fullname,
                     gpg_strerror (gpg_error_from_syserror()));
          npth_mutex_unlock (&logfile_lock);
          severe_error ();
        }

      strncpy (logfile.suffix, buffer, 8);
      logfile.suffix[8] = 0;

      xfree (logfile.fullname);
      logfile.fullname = strconcat (logfile.basename, "-", logfile.suffix,
                                    ".log", NULL);
      if (!logfile.fullname || !(logfile.fp = fopen (logfile.fullname, "a")))
        {
          log_error ("error opening '%s': %s\n",
                     logfile.fullname,
                     gpg_strerror (gpg_error_from_syserror()));
          npth_mutex_unlock (&logfile_lock);
          severe_error ();
        }
    }

  if (fputs (buffer, logfile.fp) == EOF || fflush (logfile.fp))
    {
      log_error ("error writing to logfile '%s': %s\n",
                 logfile.fullname, gpg_strerror (gpg_error_from_syserror()));
      npth_mutex_unlock (&logfile_lock);
      severe_error ();
    }

  res = npth_mutex_unlock (&logfile_lock);
  if (res)
    log_fatal ("failed to release journal writing lock: %s\n",
               gpg_strerror (gpg_error_from_errno (res)));
}



/* Close the stream FP and put its data into the queue.  */
static void
write_and_close_fp (estream_t fp)
{
  void *buffer;
  size_t buflen;

  /* Write a LF and an extra Nul so that we can use snatched memory as
     a C-string.  */
  if (es_fwrite ("\n", 2, 1, fp) != 1
      || es_fclose_snatch (fp, &buffer, &buflen))
    {
      log_error ("error closing memory stream for the journal: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      severe_error ();
    }
  if (buflen < 16)
    {
      log_error ("internal error: journal record too short (%s)\n",
                 (char*)buffer);
      severe_error ();
    }

  write_log (buffer);

  es_free (buffer);
}


/* Get the current time and put it into TIMESTAMP, which must be a
   buffer of at least TIMESTAMP_SIZE + 1 bytes.  */
static void
get_current_time (char *timestamp)
{
  time_t atime = time (NULL);
  struct tm *tp;

  if (atime == (time_t)(-1))
    {
      log_error ("time() failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      severe_error ();
    }

#ifdef HAVE_GMTIME_R
  {
    struct tm tmbuf;

    tp = gmtime_r (&atime, &tmbuf);
  }
#else
  tp = gmtime (&atime);
#endif

  snprintf (timestamp, TIMESTAMP_SIZE+1, "%04d%02d%02dT%02d%02d%02d",
            1900 + tp->tm_year, tp->tm_mon+1, tp->tm_mday,
            tp->tm_hour, tp->tm_min, tp->tm_sec);
}


/* Register the journal file.  */
void
jrnl_set_file (const char *fname)
{
  logfile.basename = xstrdup (fname);
}


static estream_t
start_record (char type, char *timestamp)
{
  estream_t fp;
  char timestamp_buffer[TIMESTAMP_SIZE + 1];

  if (!timestamp)
    timestamp = timestamp_buffer;

  fp = es_fopenmem (0, "w+,samethread");
  if (!fp)
    {
      log_error ("error creating new memory stream for the journal: %s\n",
                 gpg_strerror (gpg_error_from_syserror()));
      severe_error ();
    }

  get_current_time (timestamp);
  es_fprintf (fp, "%s:%c:", timestamp, type);
  return fp;
}


static void
write_escaped_buf (const void *buf, size_t len, estream_t fp)
{
  const unsigned char *s;

  for (s = buf; len; s++, len--)
    {
      if (!strchr (":&\n\r", *s))
        es_putc (*s, fp);
      else
        es_fprintf (fp, "%%%02X", *s);
    }
}


static void
write_escaped (const char *string, estream_t fp)
{
  write_escaped_buf (string, strlen (string), fp);
  es_putc (':', fp);
}


/* Iterate over all keys named "Meta[FOO]" for all FOO and print the
   meta data field.  */
static void
write_meta (keyvalue_t dict, estream_t fp)
{
  keyvalue_t kv;
  const char *s, *name;
  int any = 0;

  for (kv=dict; kv; kv = kv->next)
    {
      if (!strncmp (kv->name, "Meta[", 5) && kv->value && *kv->value)
        {
          name = kv->name + 5;
          for (s = name; *s; s++)
            {
              if (*s == ']')
                break;
              else if (strchr ("=& \t", *s))
                break;
            }
          if (*s != ']' || s == name || s[1])
            continue; /* Not a valid key.  */
          if (!any)
            any = 1;
          else
            es_putc ('&', fp);
          write_escaped_buf (name, s - name, fp);
          es_putc ('=', fp);
          write_escaped_buf (kv->value, strlen (kv->value), fp);
        }
    }
  es_putc (':', fp);
}


/* Store a system record in the journal. */
void
jrnl_store_sys_record (const char *text)
{
  estream_t fp;

  fp = start_record ('$', NULL);
  es_fputs (":::", fp);
  write_escaped (text, fp);
  es_fputs (":::::::::", fp);
  write_and_close_fp (fp);
}


/* Store a currency exchange record in the journal. */
void
jrnl_store_exchange_rate_record (const char *currency, double rate)
{
  estream_t fp;

  fp = start_record ('$', NULL);  /* System record.  */
  es_fprintf (fp,"1:%s:%f:new exchange rate:", currency, rate);
  es_fputs ("::::::::1.0:", fp);
  write_and_close_fp (fp);
}


/* Create a new record and spool it.  There is no error return because
   the actual transaction has already happened and we want to make
   sure to write that to the journal.  If we can't do that, we better
   stop the process to limit the number of records lost.  I consider
   it better to have a non-working web form than to have too many non
   recorded transaction.  Adds "_timestamp" record into DICT.  */
void
jrnl_store_charge_record (keyvalue_t *dictp)
{
  estream_t fp;
  char timestamp[TIMESTAMP_SIZE + 1];
  keyvalue_t dict;
  const char *curr, *amnt;
  char amountbuf[AMOUNTBUF_SIZE];

  fp = start_record ('C', timestamp);
  keyvalue_put (dictp, "_timestamp", timestamp);
  dict = *dictp;
  es_fprintf (fp, "%d:", (*keyvalue_get_string (dict, "Live") == 't'));
  write_escaped ((curr=keyvalue_get_string (dict, "Currency")), fp);
  write_escaped ((amnt=keyvalue_get_string (dict, "Amount")), fp);
  write_escaped (keyvalue_get_string (dict, "Desc"), fp);
  write_escaped (keyvalue_get_string (dict, "Email"), fp);
  write_meta (dict, fp);
  write_escaped (keyvalue_get_string (dict, "Last4"), fp);
  es_fputs ("1:", fp);  /* service: Stripe = 1 */
  es_fputs ("1:", fp);  /* account */
  write_escaped (keyvalue_get_string (dict, "Charge-Id"), fp);
  write_escaped (keyvalue_get_string (dict, "balance-transaction"), fp);
  es_fputs (":", fp);   /* rtxid */
  es_fputs (convert_currency (amountbuf, sizeof amountbuf, curr, amnt), fp);
  es_fputs (":", fp);   /* euro */

  write_and_close_fp (fp);
}
