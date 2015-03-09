/* currency.c - Currency management functions
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
#include <stdio.h>
#include <errno.h>

#include "payprocd.h"
#include "util.h"
#include "logging.h"
#include "journal.h"
#include "currency.h"

/* The file with the exchange rates.  This is expected to be created
   by a cron job and the geteuroxref script.  */
static const char euroxref_fname[] = "/var/lib/payproc/euroxref.dat";


/* The list of supported currencies  */
static struct
{
  const char *name;
  unsigned char decdigits;
  const char *desc;
  double rate;     /* Exchange rate to Euro.  */
} currency_table[] = {
  { "EUR", 2, "Euro", 1.0 },  /* Must be the first entry! */
  { "USD", 2, "US Dollar" },
  { "GBP", 2, "British Pound" },
  { "JPY", 0, "Yen" }
};


void
read_exchange_rates (void)
{
  gpg_error_t err = 0;
  estream_t fp;
  int lnr = 0;
  int n, c, idx;
  char line[256];
  char *p, *pend;
  double rate;

  fp = es_fopen (euroxref_fname, "r");
  if (!fp)
    {
      err = gpg_error_from_syserror ();
      log_error ("error opening '%s': %s\n",
                 euroxref_fname, gpg_strerror (err));
      return;
    }

  while (es_fgets (line, DIM(line)-1, fp))
    {
      lnr++;

      n = strlen (line);
      if (!n || line[n-1] != '\n')
        {
          /* Eat until end of line. */
          while ((c=es_getc (fp)) != EOF && c != '\n')
            ;
          err = gpg_error (*line? GPG_ERR_LINE_TOO_LONG
                           : GPG_ERR_INCOMPLETE_LINE);
          log_error ("error reading '%s', line %d: %s\n",
                     euroxref_fname, lnr, gpg_strerror (err));
          continue;
        }
      line[--n] = 0; /* Chop the LF. */
      if (n && line[n-1] == '\r')
        line[--n] = 0; /* Chop an optional CR. */

      /* Allow leading spaces and skip empty and comment lines. */
      for (p=line; spacep (p); p++)
        ;
      if (!*p || *p == '#')
        continue;

      /* Parse the currency name. */
      pend = strchr (p, '=');
      if (!pend)
        {
          log_error ("error parsing '%s', line %d: %s\n",
                     euroxref_fname, lnr, "missing '='");
          continue;
        }
      *pend++ = 0;
      trim_spaces (p);
      if (!*p)
        {
          log_error ("error parsing '%s', line %d: %s\n",
                     euroxref_fname, lnr, "currency name missing");
          continue;
        }

      /* Note that we start at 1 to skip the first entry which is
         EUR.  */
      for (idx=1; idx < DIM(currency_table); idx++)
        if (!strcasecmp (currency_table[idx].name, p))
          break;
      if (!(idx < DIM(currency_table)))
        continue; /* Currency not supported.  */

      /* Parse the rate. */
      p = pend;
      errno = 0;
      rate = strtod (p, &pend);
      if ((!rate && p == pend) || errno || rate <= 0.0 || rate > 10000.0)
        {
          log_error ("error parsing '%s', line %d: %s\n",
                     euroxref_fname, lnr, "invalid exchange rate");
          continue;
        }
      p = pend;
      trim_spaces (p);
      if (*p)
        {
          log_error ("error parsing '%s', line %d: %s\n",
                     euroxref_fname, lnr, "garbage after exchange rate");
          continue;
        }

      /* Update the tbale.  */
      if (currency_table[idx].rate != rate)
        {
          if (!currency_table[idx].rate)
            log_info ("setting exchange rate for %s to %.4f\n",
                      currency_table[idx].name, rate);
          else
            log_info ("changing exchange rate for %s from %.4f to %.4f\n",
                      currency_table[idx].name, currency_table[idx].rate, rate);

          currency_table[idx].rate = rate;
          jrnl_store_exchange_rate_record (currency_table[idx].name, rate);
        }
    }

  es_fclose (fp);
}


/* Return the exchange rate for CURRENCY or 0.0 is not known.  */
static double
get_exchange_rate (const char *currency)
{
  int i;

  for (i=0; i < DIM(currency_table); i++)
    if (!strcasecmp (currency, currency_table[i].name))
      return currency_table[i].rate;
  return 0.0;
}


/* Check that the currency described by STRING is valid.  Returns true
   if so.  The number of of digits after the decimal point for that
   currency is stored at R_DECDIGITS.  */
int
valid_currency_p (const char *string, int *r_decdigits)
{
  int i;

  for (i=0; i < DIM(currency_table); i++)
    if (!strcasecmp (string, currency_table[i].name))
      {
        *r_decdigits = currency_table[i].decdigits;
        return 1;
      }
  return 0;
}


/* Return information for currencies.  SEQ needs to be iterated from 0
   upwards until the function returns NULL.  If not NULL a description
   of the currency is stored at R_DESC.  if not NULL, the latest known
   exchange rate is stored at R_RATE.  */
const char *
get_currency_info (int seq, char const **r_desc, double *r_rate)
{
  if (seq < 0 || seq >= DIM (currency_table))
    return NULL;
  if (r_desc)
    *r_desc = currency_table[seq].desc;
  if (r_rate)
    *r_rate = currency_table[seq].rate;
  return currency_table[seq].name;
}


/* Convert (AMOUNT, CURRENCY) to an Euro amount and store it in BUFFER
   up to a length of BUFSIZE-1.  Returns BUFFER.  If a conversion is
   not possible an empty string is returned. */
char *
convert_currency (char *buffer, size_t bufsize,
                  const char *currency, const char *amount)
{
  double value, rate;
  char *pend;

  if (!bufsize)
    log_bug ("buffer too short in convert_currency\n");

  *buffer = 0;
  errno = 0;
  value = strtod (amount, &pend);
  if ((!value && amount == pend) || errno)
    {
      log_error ("error converting %s %s to Euro: %s\n",
                 amount, currency, strerror (errno));
      return buffer;
    }

  rate = get_exchange_rate (currency);
  if (!rate)
    {
      if (opt.verbose)
        log_info ("error converting %s %s to Euro: %s\n",
                  amount, currency, "no exchange rate available");
      return buffer;
    }
  if (rate != 1.0)
    {
      value /= rate;
      value += 0.005; /* So that snprintf rounds the value. */
    }

  if (gpgrt_snprintf (buffer, bufsize, "%.2f", value) < 0)
    {
      log_error ("error converting %s %s to Euro: %s\n",
                 amount, currency, strerror (errno));
      *buffer = 0;
      return buffer;
    }

  return buffer;
}
